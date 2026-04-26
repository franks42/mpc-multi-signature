(ns mpc-multi-signature.orchestrator.ceremony
  "Per-ceremony lifecycle. Implements the orchestrator-side statechart
   procedurally, conforming to specs/statechart-keygen.edn.

   Stage 1: keygen only, against null parties (no protocol relay; each
   party reports :ceremony/complete immediately). Sign and reshare are
   future stages."
  (:require [clojure.core.async :as a]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [mpc-multi-signature.orchestrator.party-connection :as party]
            [taoensso.trove :as log]))

(defn- transition!
  "Log a chart-conforming state transition. Pure side-effect, used so
   the run-time trail of states is queryable from telemetry."
  [ceremony-id from to]
  (log/log! {:level :info
             :id    :mpc-multi-signature.orchestrator.ceremony/transition
             :msg   "Ceremony state transition"
             :data  {:ceremony-id ceremony-id :from from :to to}}))

(defn- send-begin-to-all!
  "Statechart action :action/send-begin-to-all-participants.
   `make-begin-msg` is a function `(fn [me]) → EDN-begin-map` that
   produces the per-participant begin message — it varies per ceremony
   type but the broadcast loop is generic."
  [connections-by-role participants make-begin-msg]
  (doseq [me participants
          :let [conn (get connections-by-role me)]]
    (party/send! conn (make-begin-msg me))))

(defn- channel->role [connections-by-role ch]
  (some (fn [[r conn]] (when (identical? ch (:inbound conn)) r))
        connections-by-role))

(defn- route-protocol-message!
  "Statechart action :action/route-message. Forwards a
   :protocol/broadcast (to every other participant) or :protocol/private
   (to the named recipient) as a :protocol/deliver carrying the same
   base64 body. The orchestrator never decodes protocol bodies."
  [connections-by-role participants msg from-role]
  (let [deliver {:msg/type      :protocol/deliver
                 :ceremony/id   (:ceremony/id msg)
                 :protocol/from from-role
                 :protocol/body (:protocol/body msg)}]
    (case (:msg/type msg)
      :protocol/broadcast
      (doseq [r participants
              :when (not= r from-role)
              :let  [conn (get connections-by-role r)]
              :when conn]
        (party/send! conn deliver))

      :protocol/private
      (when-let [conn (get connections-by-role (:protocol/to msg))]
        (party/send! conn deliver)))))

(defn- await-completes
  "Block until each participant emits :ceremony/complete or the deadline
   elapses. Routes :protocol/broadcast and :protocol/private messages
   between parties as :protocol/deliver while waiting.

   Returns {:results {role result-map}} on success or
   {:error :reason/timeout :missing #{...}} on timeout. Late-arriving
   messages from a party already in :party-state/done are dropped per
   the chart's :late-protocol-message-after-final cross-cutting rule."
  [connections-by-role participants deadline-ms]
  (let [timer (a/timeout deadline-ms)
        chans (mapv #(get-in connections-by-role [% :inbound]) participants)]
    (loop [pending  (set participants)
           results  {}]
      (if (empty? pending)
        {:results results}
        (let [[v ch] (a/alts!! (conj chans timer))]
          (cond
            (= ch timer)
            {:error :reason/timeout :missing pending :results results}

            (nil? v)
            {:error :reason/party-disconnected :missing pending :results results}

            (= :ceremony/complete (:msg/type v))
            (let [role (channel->role connections-by-role ch)]
              (if (contains? pending role)
                (recur (disj pending role)
                       (assoc results role (:ceremony/result v)))
                {:error :reason/duplicate-complete :results results}))

            (#{:protocol/broadcast :protocol/private} (:msg/type v))
            (let [from-role (channel->role connections-by-role ch)]
              (route-protocol-message! connections-by-role participants v from-role)
              (recur pending results))

            (= :ceremony/error (:msg/type v))
            (let [from-role (channel->role connections-by-role ch)
                  err       (:ceremony/error v)]
              {:error   (:category err :reason/party-error)
               :message (:message err)
               :from    from-role
               :results results})

            :else
            (recur pending results)))))))

(defn- keygen-consistency-check
  "Statechart action :action/keygen-consistency-check. Returns
   {:passed? true :public-key pk} if all parties agree on
   :result/public-key-hex; {:passed? false :reason ...} otherwise."
  [results]
  (let [pks (into #{} (map :result/public-key-hex) (vals results))]
    (cond
      (= 1 (count pks))    {:passed? true :public-key (first pks)}
      (zero? (count pks))  {:passed? false :reason :reason/no-results}
      :else                {:passed? false
                            :reason :reason/public-key-disagreement
                            :public-keys pks})))

(defn- send-cancel-to-all!
  "Statechart action :action/send-cancel-to-all-participants."
  [connections-by-role participants ceremony-id reason]
  (doseq [me participants
          :let [conn (get connections-by-role me)]]
    (try (party/send! conn
                      {:msg/type        :ceremony/cancel
                       :ceremony/id     ceremony-id
                       :ceremony/reason reason})
         (catch Exception _e nil))))

(defn- run-ceremony
  "Generic ceremony lifecycle driver conforming to the keygen statechart
   template. Caller supplies `make-begin-msg` (per-role begin EDN) and
   `finalize-fn` (results-map → {:passed? bool :result map :reason kw?}).

   Returns the finalize-fn's `:result` on success, or
   {:error <reason> :ceremony/id ... :details ...} on failure."
  [{:keys [connections-by-role]} ceremony-id participants
   make-begin-msg finalize-fn deadline-ms]
  (transition! ceremony-id :state/pending :state/starting)
  (send-begin-to-all! connections-by-role participants make-begin-msg)
  (transition! ceremony-id :state/starting :state/running)
  (let [{:keys [results error] :as outcome}
        (await-completes connections-by-role participants deadline-ms)]
    (cond
      error
      (do
        (transition! ceremony-id :state/running :state/aborting)
        (send-cancel-to-all! connections-by-role participants ceremony-id error)
        (transition! ceremony-id :state/aborting :state/failed)
        (log/log! {:level :error
                   :id    :mpc-multi-signature.orchestrator.ceremony/failed
                   :msg   "Ceremony failed"
                   :data  {:ceremony-id ceremony-id :outcome outcome}})
        {:error error :ceremony/id ceremony-id :details outcome})

      :else
      (let [_ (transition! ceremony-id :state/running :state/finalizing)
            {:keys [passed? result reason] :as check} (finalize-fn results)]
        (if passed?
          (do (transition! ceremony-id :state/finalizing :state/complete)
              (log/log! {:level :info
                         :id    :mpc-multi-signature.orchestrator.ceremony/complete
                         :msg   "Ceremony complete"
                         :data  {:ceremony-id ceremony-id
                                 :result (dissoc result :raw-results)}})
              result)
          (do (transition! ceremony-id :state/finalizing :state/aborting)
              (send-cancel-to-all! connections-by-role participants ceremony-id reason)
              (transition! ceremony-id :state/aborting :state/failed)
              (log/log! {:level :error
                         :id    :mpc-multi-signature.orchestrator.ceremony/finalization-failed
                         :data  {:ceremony-id ceremony-id :check check}})
              {:error reason :ceremony/id ceremony-id :details check}))))))

(defn run-keygen
  "Drive a keygen ceremony; returns
     {:public-key <hex> :share-handle <uuid> :handles {role <uuid>} :ceremony/id <uuid>}
   on success."
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold deadline-ms]
    :or   {threshold 2 deadline-ms 30000}}]
  (let [ceremony-id  (uuidv7/uuidv7)
        share-handle (uuidv7/uuidv7)
        peers        (vec participants)
        ids          (select-keys participant-ids peers)
        peer-pubkeys (select-keys identity-pubkeys peers)
        make-begin   (fn [me]
                       {:msg/type              :ceremony/begin-keygen
                        :ceremony/id           ceremony-id
                        :ceremony/me           me
                        :ceremony/peers        peers
                        :ceremony/participant-ids ids
                        :ceremony/peer-pubkeys peer-pubkeys
                        :ceremony/threshold    threshold
                        :ceremony/share-handle share-handle})
        finalize     (fn [results]
                       (let [check (keygen-consistency-check results)]
                         (if (:passed? check)
                           {:passed? true
                            :result {:public-key          (:public-key check)
                                     :share-handle        share-handle
                                     :handles             (into {} (for [r peers] [r share-handle]))
                                     ;; Per-party verification shares —
                                     ;; the X_i = x_i·G commitment used
                                     ;; by Stage 5+ share-possession proofs.
                                     :verification-shares (into {}
                                                                (for [[r m] results]
                                                                  [r (:result/verification-share-hex m)]))
                                     :ceremony/id         ceremony-id}}
                           {:passed? false :reason (:reason check) :details check})))]
    (run-ceremony orch ceremony-id peers make-begin finalize deadline-ms)))

;; ============================================================
;; Stage 4 ceremonies: triple-generation, presign, sign, reshare
;; ============================================================

(defn run-triple-generation
  "Drive a triple-generation ceremony. Each party produces shares of
   two Beaver triples (consumed together by one presign). Result:
     {:triple-handle <uuid> :handles {role uuid} :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold deadline-ms]
    :or   {threshold 2 deadline-ms 60000}}]
  (let [ceremony-id   (uuidv7/uuidv7)
        triple-handle (uuidv7/uuidv7)
        peers         (vec participants)
        ids           (select-keys participant-ids peers)
        peer-pubkeys  (select-keys identity-pubkeys peers)
        make-begin    (fn [me]
                        {:msg/type              :ceremony/begin-triples
                         :ceremony/id           ceremony-id
                         :ceremony/me           me
                         :ceremony/peers        peers
                         :ceremony/participant-ids ids
                         :ceremony/peer-pubkeys peer-pubkeys
                         :ceremony/threshold    threshold
                         :ceremony/triple-handle triple-handle})
        finalize      (fn [_results]
                        ;; Triples have no cross-party consistency check
                        ;; on the orchestrator side; we trust the protocol.
                        {:passed? true
                         :result  {:triple-handle triple-handle
                                   :handles       (into {} (for [r peers] [r triple-handle]))
                                   :ceremony/id   ceremony-id}})]
    (run-ceremony orch ceremony-id peers make-begin finalize deadline-ms)))

(defn run-presign
  "Drive a presign ceremony, consuming a keygen share + a triple pair,
   producing a presignature stored per-party. Result:
     {:presig-handle <uuid> :handles {role uuid} :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold share-handle triple-handle deadline-ms]
    :or   {threshold 2 deadline-ms 60000}}]
  (assert share-handle  "run-presign: :share-handle required")
  (assert triple-handle "run-presign: :triple-handle required")
  (let [ceremony-id   (uuidv7/uuidv7)
        presig-handle (uuidv7/uuidv7)
        peers         (vec participants)
        ids           (select-keys participant-ids peers)
        peer-pubkeys  (select-keys identity-pubkeys peers)
        make-begin    (fn [me]
                        {:msg/type              :ceremony/begin-presign
                         :ceremony/id           ceremony-id
                         :ceremony/me           me
                         :ceremony/peers        peers
                         :ceremony/participant-ids ids
                         :ceremony/peer-pubkeys peer-pubkeys
                         :ceremony/threshold    threshold
                         :ceremony/share-handle share-handle
                         :ceremony/triple-handle triple-handle
                         :ceremony/presig-handle presig-handle})
        finalize      (fn [_results]
                        {:passed? true
                         :result  {:presig-handle presig-handle
                                   :handles       (into {} (for [r peers] [r presig-handle]))
                                   :ceremony/id   ceremony-id}})]
    (run-ceremony orch ceremony-id peers make-begin finalize deadline-ms)))

(defn- sign-consistency-check
  "Statechart action :action/sign-consistency-check. The coordinator
   returns the signature; non-coordinators return null. Verify that
   exactly one party returned a non-null signature."
  [results coordinator]
  (let [coord-result (get results coordinator)
        sig          (:result/signature-hex coord-result)
        non-coord-sigs (->> (dissoc results coordinator)
                            vals
                            (map :result/signature-hex)
                            (remove nil?))]
    (cond
      (nil? sig)
      {:passed? false :reason :reason/no-signature-from-coordinator}

      (seq non-coord-sigs)
      {:passed? false :reason :reason/non-coordinator-emitted-signature}

      :else
      {:passed? true :signature-hex sig})))

(defn run-sign
  "Drive a sign ceremony. Consumes the keygen share and a presignature;
   the coordinator party produces an ECDSA signature. Result:
     {:signature-hex <64-byte raw r||s in hex>
      :coordinator <role>  :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold coordinator share-handle presig-handle digest-hex deadline-ms]
    :or   {threshold 2 deadline-ms 60000}}]
  (assert share-handle  "run-sign: :share-handle required")
  (assert presig-handle "run-sign: :presig-handle required")
  (assert digest-hex    "run-sign: :digest-hex required (32-byte hex)")
  (assert coordinator   "run-sign: :coordinator required (role keyword)")
  (let [ceremony-id  (uuidv7/uuidv7)
        peers        (vec participants)
        ids          (select-keys participant-ids peers)
        peer-pubkeys (select-keys identity-pubkeys peers)
        make-begin   (fn [me]
                       {:msg/type              :ceremony/begin-sign
                        :ceremony/id           ceremony-id
                        :ceremony/me           me
                        :ceremony/peers        peers
                        :ceremony/participant-ids ids
                        :ceremony/peer-pubkeys peer-pubkeys
                        :ceremony/threshold    threshold
                        :ceremony/coordinator  coordinator
                        :ceremony/share-handle share-handle
                        :ceremony/presig-handle presig-handle
                        :ceremony/digest-hex   digest-hex})
        finalize    (fn [results]
                      (let [check (sign-consistency-check results coordinator)]
                        (if (:passed? check)
                          {:passed? true
                           :result {:signature-hex (:signature-hex check)
                                    :coordinator   coordinator
                                    :ceremony/id   ceremony-id}}
                          {:passed? false :reason (:reason check)
                           :details {:results results}})))]
    (run-ceremony orch ceremony-id peers make-begin finalize deadline-ms)))

(defn- reshare-consistency-check
  "Reshare must preserve the public key. All new participants report
   their post-reshare public-key-hex; all must match the original
   public-key passed in."
  [results expected-pk-hex]
  (let [pks (into #{} (map :result/public-key-hex) (vals results))]
    (cond
      (= 1 (count pks)) (let [pk (first pks)]
                          (if (= pk expected-pk-hex)
                            {:passed? true :public-key pk}
                            {:passed? false
                             :reason :reason/public-key-not-preserved
                             :expected expected-pk-hex
                             :got pk}))
      :else {:passed? false :reason :reason/public-key-disagreement
             :public-keys pks})))

(defn run-reshare
  "Drive a reshare ceremony — `old-participants` and `new-participants`
   may differ (UC2: holder→new-holder, with figure+ic continuing). All
   parties in the union of old+new participate.
   Result: {:public-key <preserved hex> :share-handle <new uuid>
            :handles {role uuid} :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch}
   {:keys [old-participants new-participants old-threshold new-threshold
           old-share-handle public-key-hex deadline-ms]
    :or   {old-threshold 2 new-threshold 2 deadline-ms 60000}}]
  (assert public-key-hex "run-reshare: :public-key-hex required (continuity anchor)")
  (let [ceremony-id      (uuidv7/uuidv7)
        new-share-handle (uuidv7/uuidv7)
        ;; Per the threshold-signatures reshare API: only new_participants
        ;; run the Protocol. Old-only participants (those in old but not
        ;; new — e.g. UC2's lost holder) are NOT protocol runners; their
        ;; shares are referenced via the algorithm's old_participants
        ;; metadata in the begin message but they don't exchange protocol
        ;; messages.
        protocol-runners new-participants
        ;; Canonical ids for both old and new — needed by the protocol
        ;; algorithm even for old-only parties (referenced in metadata).
        all-roles        (distinct (concat old-participants new-participants))
        ids              (select-keys participant-ids all-roles)
        peer-pubkeys     (select-keys identity-pubkeys protocol-runners)
        make-begin       (fn [me]
                           {:msg/type                 :ceremony/begin-reshare
                            :ceremony/id              ceremony-id
                            :ceremony/me              me
                            :ceremony/old-peers       (vec old-participants)
                            :ceremony/old-threshold   old-threshold
                            :ceremony/new-peers       (vec new-participants)
                            :ceremony/new-threshold   new-threshold
                            :ceremony/participant-ids ids
                            :ceremony/peer-pubkeys    peer-pubkeys
                            :ceremony/old-share-handle (when (some #{me} old-participants)
                                                         old-share-handle)
                            :ceremony/new-share-handle new-share-handle
                            :ceremony/public-key-hex   public-key-hex})
        finalize         (fn [results]
                           (let [check (reshare-consistency-check
                                        results public-key-hex)]
                             (if (:passed? check)
                               {:passed? true
                                :result {:public-key          (:public-key check)
                                         :share-handle        new-share-handle
                                         :handles             (into {}
                                                                    (for [r new-participants]
                                                                      [r new-share-handle]))
                                         ;; Refresh verification shares for the new shareset.
                                         :verification-shares (into {}
                                                                    (for [[r m] results]
                                                                      [r (:result/verification-share-hex m)]))
                                         :ceremony/id         ceremony-id}}
                               {:passed? false :reason (:reason check) :details check})))]
    (run-ceremony orch ceremony-id protocol-runners make-begin finalize deadline-ms)))

;; ============================================================
;; Stage 5a: share-possession proof
;; ============================================================

(defn run-share-possession-proof
  "Each participating party produces a Schnorr PoK against a challenge
   context, demonstrating possession of their share without producing
   a real signature.

   Challenge-context modes:
     :challenge-context-hex <hex>
       Uniform challenge context; every party gets the same bytes.
     :challenge-context-hex-by-role {role <hex> ...}
       Per-party challenge contexts — required for identity-share
       binding proofs (each party's context is bound to their own
       identity public key).

   Optional :binding-mode? true (Stage 5b.2): instructs each bb
   wrapper to additionally sign the Schnorr proof bytes with its own
   Ed25519 identity key after crypto-core emits the transcript. The
   per-party result then carries :result/identity-pubkey-hex and
   :result/identity-signature-hex on top of the basic transcript.

   Result:
     {:proofs {role {:verification-share-hex ... :proof-hex ...
                     :challenge-context-hex ...
                     :identity-pubkey-hex ... ; binding mode only
                     :identity-signature-hex ...}} ; binding mode only
      :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [share-handle challenge-context-hex challenge-context-hex-by-role
           binding-mode? deadline-ms]
    :or   {deadline-ms 30000}}]
  (assert share-handle "run-share-possession-proof: :share-handle required")
  (assert (or challenge-context-hex challenge-context-hex-by-role)
          "run-share-possession-proof: :challenge-context-hex or :challenge-context-hex-by-role required")
  (let [ceremony-id  (uuidv7/uuidv7)
        peers        (vec participants)
        ids          (select-keys participant-ids peers)
        peer-pubkeys (select-keys identity-pubkeys peers)
        ctx-for      (fn [me]
                       (or (get challenge-context-hex-by-role me)
                           challenge-context-hex))
        make-begin   (fn [me]
                       (cond-> {:msg/type                       :ceremony/begin-share-proof
                                :ceremony/id                    ceremony-id
                                :ceremony/me                    me
                                :ceremony/participant-ids       ids
                                :ceremony/peer-pubkeys          peer-pubkeys
                                :ceremony/share-handle          share-handle
                                :ceremony/challenge-context-hex (ctx-for me)}
                         binding-mode? (assoc :ceremony/binding-mode? true)))
        finalize    (fn [results]
                      {:passed? true
                       :result  {:proofs      (into {}
                                                    (for [[r m] results]
                                                      [r (cond-> {:verification-share-hex (:result/verification-share-hex m)
                                                                  :proof-hex              (:result/proof-hex m)
                                                                  :challenge-context-hex  (ctx-for r)}
                                                           binding-mode?
                                                           (assoc :identity-pubkey-hex    (:result/identity-pubkey-hex m)
                                                                  :identity-signature-hex (:result/identity-signature-hex m)))]))
                                 :ceremony/id ceremony-id}})]
    (run-ceremony orch ceremony-id peers make-begin finalize deadline-ms)))
