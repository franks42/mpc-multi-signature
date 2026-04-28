(ns mpc-multi-signature.orchestrator.chart-driven
  "Chart-driven ceremony runtime. Pairs with the executable charts
   under specs/executable/.

   Patterns this implementation embodies are documented in
   docs/statechart-best-practices.md.

   Plumbing context fields (namespaced :: keys) carry orchestrator
   handle, internal-events queue, result promise, ceremony-specific
   make-begin and build-result functions. They are inserted into the
   FSM context before initialization and consumed by the action/guard
   functions."
  (:require [clojure.core.async :as a]
            [clojure.edn :as edn]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [mpc-multi-signature.orchestrator.chart-runtime :as cr]
            [mpc-multi-signature.orchestrator.party-connection :as party]
            [statecharts.core :as fsm]
            [taoensso.trove :as log]))

;; ============================================================
;; Actions
;; ============================================================
;;
;; Two flavors:
;;
;;   - SIDE-EFFECT actions (sending messages, queueing events,
;;     delivering to a promise): plain (fn [state event] -> state).
;;     Return state unchanged; clj-statecharts threads the prior state.
;;
;;   - CONTEXT-UPDATING actions (record-party-done etc.): wrapped with
;;     `(fsm/assign (fn [state event] -> state'))`. clj-statecharts
;;     ignores plain return values from actions and only applies an
;;     update if the action returns a ContextAssignment record (which
;;     fsm/assign produces). Without the wrapper, context updates are
;;     silently discarded — a non-obvious gotcha but documented in
;;     the impl source (statecharts/impl.cljc execute fn).

(defn- send-begin-to-all-participants
  [{:keys [::orch ::participants ::make-begin] :as state} _event]
  (doseq [me participants
          :let [conn (get-in orch [:connections-by-role me])]
          :when conn]
    (party/send! conn (make-begin me)))
  state)

(defn- start-deadline-timer
  ;; Real deadline tracking is in the event loop's a/timeout. This
  ;; action is a structural marker confirming the deadline is now armed.
  [state _event]
  state)

(defn- route-message
  "Single home for protocol-message routing. Mirrors
   ceremony/route-protocol-message! exactly."
  [{:keys [::orch ::participants] :as state}
   {:protocol/keys [from body to] msg-type :msg/type ceremony-id :ceremony/id}]
  (let [deliver {:msg/type      :protocol/deliver
                 :ceremony/id   ceremony-id
                 :protocol/from from
                 :protocol/body body}]
    (case msg-type
      :protocol/broadcast
      (doseq [r participants
              :when (not= r from)
              :let  [conn (get-in orch [:connections-by-role r])]
              :when conn]
        (party/send! conn deliver))

      :protocol/private
      (when-let [conn (get-in orch [:connections-by-role to])]
        (party/send! conn deliver))

      (log/log! {:level :warn
                 :id    :mpc-multi-signature.orchestrator.chart-driven/unknown-route
                 :data  {:msg-type msg-type}})))
  state)

(def ^:private record-party-done
  (fsm/assign
   (fn [state {:keys [from result]}]
     (-> state
         (assoc-in [:ceremony/per-party-state from] :party-state/done)
         (assoc-in [:ceremony/results from] result)))))

(defn- collect-per-party-results
  ;; Triple-gen carries per-party results in :ceremony/results already;
  ;; this action is a marker.
  [state _event]
  state)

(defn- check-results-collected
  "Generic shape check for ceremonies with no orchestrator-side
   cross-party consistency check (triple-gen, presign). Confirms every
   participant returned a result map, then queues
   :event/finalization-passed (or -failed). Charts that need this
   reference it via ceremony-specific action keywords (e.g.
   :action/triple-shape-check, :action/presig-shape-check) — both
   resolve to this same function."
  [{:keys [::participants ::pending-events :ceremony/results] :as state}
   _event]
  (let [ok? (every? #(some? (get results %)) participants)]
    (swap! pending-events conj
           (if ok? :event/finalization-passed :event/finalization-failed))
    state))

(def ^:private sign-consistency-check
  "Sign-specific finalization check. The coordinator returns a
   signature; non-coordinators return nil for the signature field.
   Verify exactly one party (the named coordinator) returned a non-nil
   :result/signature-hex; populate :ceremony/signature-hex; queue
   :event/finalization-passed (or -failed)."
  (fsm/assign
   (fn [{:keys [::pending-events :ceremony/coordinator :ceremony/results]
         :as state} _event]
     (let [coord-sig    (get-in results [coordinator :result/signature-hex])
           non-coord-sigs (->> (dissoc results coordinator)
                               vals
                               (map :result/signature-hex)
                               (remove nil?))]
       (cond
         (nil? coord-sig)
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/no-signature-from-coordinator))

         (seq non-coord-sigs)
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/non-coordinator-emitted-signature))

         :else
         (do (swap! pending-events conj :event/finalization-passed)
             (assoc state :ceremony/signature-hex coord-sig)))))))

(def ^:private reshare-consistency-check
  "Reshare-specific finalization check. Every new participant must
   report the SAME public-key-hex AND it must equal
   :ceremony/expected-public-key-hex (continuity anchor passed in at
   ceremony start). Populates :ceremony/public-key +
   :ceremony/verification-shares on success."
  (fsm/assign
   (fn [{:keys [::pending-events :ceremony/results
                :ceremony/expected-public-key-hex]
         :as state} _event]
     (let [pks (->> results vals (map :result/public-key-hex) (into #{}))]
       (cond
         (and (= 1 (count pks))
              (= (first pks) expected-public-key-hex))
         (do (swap! pending-events conj :event/finalization-passed)
             (-> state
                 (assoc :ceremony/public-key (first pks))
                 (assoc :ceremony/verification-shares
                        (into {} (for [[r m] results]
                                   [r (:result/verification-share-hex m)])))))

         (and (= 1 (count pks))
              (not= (first pks) expected-public-key-hex))
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/public-key-not-preserved))

         :else
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/public-key-disagreement)))))))

(def ^:private keygen-consistency-check
  "Keygen-specific finalization check. Reads per-party results and
   verifies all parties report the same public-key-hex. On agreement:
   stores :ceremony/public-key + :ceremony/verification-shares in
   context, queues :event/finalization-passed. On disagreement:
   stores :ceremony/error reason, queues :event/finalization-failed.

   Wrapped in fsm/assign because it updates context. Side effect on
   the pending-events atom happens before the assignment is returned."
  (fsm/assign
   (fn [{:keys [::pending-events :ceremony/results] :as state} _event]
     (let [pks (->> results vals (map :result/public-key-hex) (into #{}))]
       (cond
         (= 1 (count pks))
         (do (swap! pending-events conj :event/finalization-passed)
             (-> state
                 (assoc :ceremony/public-key (first pks))
                 (assoc :ceremony/verification-shares
                        (into {} (for [[r m] results]
                                   [r (:result/verification-share-hex m)])))))

         (zero? (count pks))
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/no-results))

         :else
         (do (swap! pending-events conj :event/finalization-failed)
             (assoc state :ceremony/error :reason/public-key-disagreement)))))))

(defn- notify-coordinator-success
  "Generic success-notification. The ceremony-specific result shape is
   built by the ::build-result fn supplied in plumbing context — this
   keeps the action generic across ceremonies. Each entry-point
   (run-triple-generation-via-chart, run-keygen-via-chart, ...) wires
   its own ::build-result builder."
  [{:keys [::result-promise ::build-result] :as state} _event]
  (deliver result-promise (build-result state))
  state)

(defn- persist-result-handles
  [state _event]
  state)

(defn- send-cancel-to-all-participants
  [{:keys [::orch ::participants :ceremony/id :ceremony/error] :as state} _event]
  (let [reason (or error :reason/cancel)]
    (doseq [me participants
            :let [conn (get-in orch [:connections-by-role me])]
            :when conn]
      (try (party/send! conn {:msg/type        :ceremony/cancel
                              :ceremony/id     id
                              :ceremony/reason reason})
           (catch Exception _e nil))))
  state)

(defn- start-abort-timeout
  [{:keys [::pending-events] :as state} _event]
  (swap! pending-events conj :event/abort-timeout-elapsed)
  state)

(def ^:private record-error
  (fsm/assign
   (fn [state {:keys [error]}]
     (assoc state :ceremony/error (or error :reason/error)))))

(def ^:private record-erroring-party
  (fsm/assign
   (fn [state {:keys [from]}]
     (assoc state :ceremony/erroring-party from))))

(def ^:private record-cancel-reason
  (fsm/assign
   (fn [state _event]
     (assoc state :ceremony/error :reason/cancel))))

(def ^:private record-timeout
  (fsm/assign
   (fn [state _event]
     (assoc state :ceremony/error :reason/timeout))))

(defn- record-handles
  ;; Handles are placed in context at FSM init; structural marker.
  [state _event]
  state)

(defn- notify-coordinator-failure
  [{:keys [::result-promise :ceremony/error] :as state} _event]
  (deliver result-promise {:error (or error :reason/unknown)
                           :details (select-keys state [:ceremony/id
                                                        :ceremony/erroring-party
                                                        :ceremony/per-party-state])})
  state)

;; ============================================================
;; Guards
;; ============================================================

(defn- count-done [state]
  (->> (:ceremony/per-party-state state) vals
       (filter #(= :party-state/done %)) count))

(defn- guard-at-least-one-party-still-running [& _args]
  (fn [state _event]
    (let [n (count (:ceremony/participants state))
          k (count-done state)]
      ;; After this event lands, k+1 parties are done. Strictly more
      ;; than one still running iff (n - (k+1)) >= 1, i.e. (k+1) < n.
      (< (inc k) n))))

(defn- guard-all-parties-done-after-this-event [& _args]
  (fn [state _event]
    (let [n (count (:ceremony/participants state))
          k (count-done state)]
      (= (inc k) n))))

;; ============================================================
;; Registries
;; ============================================================

(def ^:private action-registry
  {:action/record-handles                   record-handles
   :action/send-begin-to-all-participants   send-begin-to-all-participants
   :action/start-deadline-timer             start-deadline-timer
   :action/route-message                    route-message
   :action/record-party-done                record-party-done
   :action/collect-per-party-results        collect-per-party-results
   ;; Ceremony-specific action keywords aliased to the same
   ;; "every party returned a result" check function. Used by
   ;; ceremonies that have no orchestrator-side cross-party check —
   ;; the protocol's own verification or the verifier's downstream
   ;; check governs correctness.
   :action/triple-shape-check               check-results-collected
   :action/presig-shape-check               check-results-collected
   :action/share-proof-shape-check          check-results-collected
   :action/keygen-consistency-check         keygen-consistency-check
   :action/sign-consistency-check           sign-consistency-check
   :action/reshare-consistency-check        reshare-consistency-check
   :action/notify-coordinator-success       notify-coordinator-success
   :action/persist-result-handles           persist-result-handles
   :action/send-cancel-to-all-participants  send-cancel-to-all-participants
   :action/start-abort-timeout              start-abort-timeout
   :action/record-error                     record-error
   :action/record-erroring-party            record-erroring-party
   :action/record-cancel-reason             record-cancel-reason
   :action/record-timeout                   record-timeout
   :action/notify-coordinator-failure       notify-coordinator-failure})

(def ^:private guard-registry
  {'guard/at-least-one-party-still-running  guard-at-least-one-party-still-running
   'guard/all-parties-done-after-this-event guard-all-parties-done-after-this-event})

;; ============================================================
;; Peer-message → FSM-event translation
;; ============================================================

(defn- channel->role [orch ch]
  (some (fn [[r conn]] (when (identical? ch (:inbound conn)) r))
        (:connections-by-role orch)))

(defn- msg->event
  [msg from-role]
  (when (map? msg)
    (case (:msg/type msg)
      (:protocol/broadcast :protocol/private)
      (-> msg (assoc :type :event/protocol-message-emit :from from-role))

      :ceremony/complete
      {:type :event/ceremony-complete
       :from from-role
       :result (:ceremony/result msg)}

      :ceremony/error
      {:type  :event/ceremony-error
       :from  from-role
       :error (or (:category (:ceremony/error msg)) :reason/party-error)}

      nil)))

;; ============================================================
;; Event loop
;; ============================================================

(defn- terminal? [state]
  (#{:state/complete :state/failed} (:_state state)))

(defn- drain-pending-events!
  [machine state-atom pending-events]
  (loop []
    (when-let [evt (first @pending-events)]
      (swap! pending-events #(vec (rest %)))
      (swap! state-atom #(fsm/transition machine % evt))
      (when-not (terminal? @state-atom)
        (recur)))))

(defn- transition-and-drain!
  [machine state-atom pending-events event]
  (swap! state-atom #(fsm/transition machine % event))
  (when-not (terminal? @state-atom)
    (drain-pending-events! machine state-atom pending-events)))

(defn- run-event-loop!
  [machine state-atom pending-events orch participants deadline-ms]
  (let [timer (a/timeout deadline-ms)
        chans (mapv #(get-in orch [:connections-by-role % :inbound]) participants)]
    (loop []
      (cond
        (terminal? @state-atom)
        :done

        :else
        (let [[v ch] (a/alts!! (conj chans timer))]
          (cond
            (= ch timer)
            (transition-and-drain! machine state-atom pending-events
                                   {:type :event/deadline-elapsed})

            (nil? v)
            (transition-and-drain! machine state-atom pending-events
                                   {:type :event/cancel})

            :else
            (let [from-role (channel->role orch ch)
                  event     (msg->event v from-role)]
              (when event
                (transition-and-drain! machine state-atom pending-events event))))
          (recur))))))

;; ============================================================
;; Generic FSM driver
;; ============================================================

(defn- run-chart-fsm!
  "Generic chart-driven ceremony driver. Loads the chart at
   `chart-path`, builds the FSM, populates context with the supplied
   `domain-context` map (the :ceremony/* fields specific to this
   ceremony) plus plumbing context (orch, participants, make-begin,
   build-result, result-promise, pending-events), fires
   :event/begin-ceremony, runs the event loop, returns the delivered
   result.

   Each ceremony entry point (run-keygen-via-chart,
   run-triple-generation-via-chart) just supplies the chart, the
   make-begin and build-result functions, the participant set, and
   the deadline."
  [orch participants chart-path domain-context make-begin build-result deadline-ms]
  (let [chart       (edn/read-string {:default tagged-literal} (slurp chart-path))
        machine     (fsm/machine
                     (cr/chart->machine-spec chart action-registry guard-registry))
        result-promise (promise)
        pending-events (atom [])
        initial-context
        (merge domain-context
               {:ceremony/per-party-state (into {} (for [r participants]
                                                     [r :party-state/awaiting]))
                :ceremony/results         {}
                :ceremony/error           nil
                ::orch                    orch
                ::participants            participants
                ::make-begin              make-begin
                ::build-result            build-result
                ::result-promise          result-promise
                ::pending-events          pending-events})
        state-atom (atom (fsm/initialize machine {:context initial-context}))]
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.chart-driven/started
               :data  {:ceremony-id   (:ceremony/id domain-context)
                       :participants  participants
                       :chart-path    chart-path}})
    (transition-and-drain! machine state-atom pending-events
                           {:type :event/begin-ceremony})
    (run-event-loop! machine state-atom pending-events orch participants deadline-ms)
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.chart-driven/ended
               :data  {:ceremony-id (:ceremony/id domain-context)
                       :final-state (:_state @state-atom)}})
    @result-promise))

;; ============================================================
;; Entry points — one per ceremony kind
;; ============================================================

(defn run-triple-generation-via-chart
  "Chart-driven equivalent of ceremony/run-triple-generation. On success:
     {:triple-handle <uuid> :handles {role <uuid>} :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold deadline-ms share-handle chart-path]
    :or   {threshold 2
           deadline-ms 60000
           chart-path  "../specs/executable/statechart-triple-generation.edn"}}]
  (let [ceremony-id   (uuidv7/uuidv7)
        triple-handle (uuidv7/uuidv7)
        peers         (vec participants)
        ids           (select-keys participant-ids peers)
        peer-pubkeys  (select-keys identity-pubkeys peers)
        make-begin    (fn [me]
                        {:msg/type                 :ceremony/begin-triples
                         :ceremony/id              ceremony-id
                         :ceremony/me              me
                         :ceremony/peers           peers
                         :ceremony/participant-ids ids
                         :ceremony/peer-pubkeys    peer-pubkeys
                         :ceremony/threshold       threshold
                         :ceremony/share-handle    share-handle
                         :ceremony/triple-handle   triple-handle})
        build-result  (fn [_state]
                        {:triple-handle triple-handle
                         :handles       (into {} (for [r peers] [r triple-handle]))
                         :ceremony/id   ceremony-id})
        domain-ctx    {:ceremony/id            ceremony-id
                       :ceremony/participants  peers
                       :ceremony/share-handle  share-handle
                       :ceremony/triple-handle triple-handle}]
    (run-chart-fsm! orch peers chart-path domain-ctx make-begin build-result
                    deadline-ms)))

(defn run-presign-via-chart
  "Chart-driven equivalent of ceremony/run-presign. Consumes a
   share-handle (from keygen) and a triple-handle (from triple-gen);
   produces a fresh presig-handle. On success:
     {:presig-handle <uuid> :handles {role <uuid>} :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold deadline-ms share-handle triple-handle chart-path]
    :or   {threshold 2
           deadline-ms 60000
           chart-path  "../specs/executable/statechart-presign.edn"}}]
  (assert share-handle  "run-presign-via-chart: :share-handle required")
  (assert triple-handle "run-presign-via-chart: :triple-handle required")
  (let [ceremony-id   (uuidv7/uuidv7)
        presig-handle (uuidv7/uuidv7)
        peers         (vec participants)
        ids           (select-keys participant-ids peers)
        peer-pubkeys  (select-keys identity-pubkeys peers)
        make-begin    (fn [me]
                        {:msg/type                 :ceremony/begin-presign
                         :ceremony/id              ceremony-id
                         :ceremony/me              me
                         :ceremony/peers           peers
                         :ceremony/participant-ids ids
                         :ceremony/peer-pubkeys    peer-pubkeys
                         :ceremony/threshold       threshold
                         :ceremony/share-handle    share-handle
                         :ceremony/triple-handle   triple-handle
                         :ceremony/presig-handle   presig-handle})
        build-result  (fn [_state]
                        {:presig-handle presig-handle
                         :handles       (into {} (for [r peers] [r presig-handle]))
                         :ceremony/id   ceremony-id})
        domain-ctx    {:ceremony/id            ceremony-id
                       :ceremony/participants  peers
                       :ceremony/share-handle  share-handle
                       :ceremony/triple-handle triple-handle
                       :ceremony/presig-handle presig-handle}]
    (run-chart-fsm! orch peers chart-path domain-ctx make-begin build-result
                    deadline-ms)))

(defn run-reshare-via-chart
  "Chart-driven equivalent of ceremony/run-reshare. Covers all three
   reshare flavors: recovery (old-peers ≠ new-peers, lost holder
   replaced), refresh (old-peers == new-peers, fresh polynomial),
   and divorce (old-peers ≠ new-peers, member removed).

   Per cait-sith, only new-participants run the protocol; old-only
   participants are referenced via begin-message metadata.

   On success:
     {:public-key <preserved hex>
      :share-handle <new uuid>
      :handles {role <uuid>}
      :verification-shares {role <hex>}
      :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch}
   {:keys [old-participants new-participants old-threshold new-threshold
           old-share-handle public-key-hex deadline-ms chart-path]
    :or   {old-threshold 2
           new-threshold 2
           deadline-ms   60000
           chart-path    "../specs/executable/statechart-reshare.edn"}}]
  (assert public-key-hex "run-reshare-via-chart: :public-key-hex required (continuity anchor)")
  (let [ceremony-id      (uuidv7/uuidv7)
        new-share-handle (uuidv7/uuidv7)
        protocol-runners (vec new-participants)
        all-roles        (distinct (concat old-participants new-participants))
        ids              (select-keys participant-ids all-roles)
        peer-pubkeys     (select-keys identity-pubkeys protocol-runners)
        make-begin       (fn [me]
                           {:msg/type                  :ceremony/begin-reshare
                            :ceremony/id               ceremony-id
                            :ceremony/me               me
                            :ceremony/old-peers        (vec old-participants)
                            :ceremony/old-threshold    old-threshold
                            :ceremony/new-peers        (vec new-participants)
                            :ceremony/new-threshold    new-threshold
                            :ceremony/participant-ids  ids
                            :ceremony/peer-pubkeys     peer-pubkeys
                            :ceremony/old-share-handle (when (some #{me} old-participants)
                                                         old-share-handle)
                            :ceremony/new-share-handle new-share-handle
                            :ceremony/public-key-hex   public-key-hex})
        build-result     (fn [state]
                           {:public-key          (:ceremony/public-key state)
                            :share-handle        new-share-handle
                            :handles             (into {} (for [r protocol-runners]
                                                            [r new-share-handle]))
                            :verification-shares (:ceremony/verification-shares state)
                            :ceremony/id         ceremony-id})
        domain-ctx       {:ceremony/id                      ceremony-id
                          :ceremony/participants            protocol-runners
                          :ceremony/expected-public-key-hex public-key-hex
                          :ceremony/old-share-handle        old-share-handle
                          :ceremony/new-share-handle        new-share-handle}]
    (run-chart-fsm! orch protocol-runners chart-path domain-ctx
                    make-begin build-result deadline-ms)))

(defn run-sign-via-chart
  "Chart-driven equivalent of ceremony/run-sign. Consumes the keygen
   share-handle, a presig-handle, and a 32-byte digest-hex; the
   named coordinator party produces an ECDSA signature. On success:
     {:signature-hex <r||s in hex>
      :coordinator <role>
      :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold coordinator share-handle presig-handle digest-hex
           deadline-ms chart-path]
    :or   {threshold 2
           deadline-ms 60000
           chart-path  "../specs/executable/statechart-sign.edn"}}]
  (assert share-handle  "run-sign-via-chart: :share-handle required")
  (assert presig-handle "run-sign-via-chart: :presig-handle required")
  (assert digest-hex    "run-sign-via-chart: :digest-hex required (32-byte hex)")
  (assert coordinator   "run-sign-via-chart: :coordinator required (role keyword)")
  (let [ceremony-id  (uuidv7/uuidv7)
        peers        (vec participants)
        ids          (select-keys participant-ids peers)
        peer-pubkeys (select-keys identity-pubkeys peers)
        make-begin   (fn [me]
                       {:msg/type                 :ceremony/begin-sign
                        :ceremony/id              ceremony-id
                        :ceremony/me              me
                        :ceremony/peers           peers
                        :ceremony/participant-ids ids
                        :ceremony/peer-pubkeys    peer-pubkeys
                        :ceremony/threshold       threshold
                        :ceremony/coordinator     coordinator
                        :ceremony/share-handle    share-handle
                        :ceremony/presig-handle   presig-handle
                        :ceremony/digest-hex      digest-hex})
        build-result (fn [state]
                       {:signature-hex (:ceremony/signature-hex state)
                        :coordinator   coordinator
                        :ceremony/id   ceremony-id})
        domain-ctx   {:ceremony/id            ceremony-id
                      :ceremony/participants  peers
                      :ceremony/coordinator   coordinator
                      :ceremony/share-handle  share-handle
                      :ceremony/presig-handle presig-handle
                      :ceremony/digest-hex    digest-hex}]
    (run-chart-fsm! orch peers chart-path domain-ctx make-begin build-result
                    deadline-ms)))

(defn run-share-possession-proof-via-chart
  "Chart-driven equivalent of ceremony/run-share-possession-proof. Each
   participating party produces a Schnorr PoK against a verifier-supplied
   challenge context. With :binding-mode? true, parties also sign the
   proof bytes with their Ed25519 identity key.

   Challenge-context modes:
     :challenge-context-hex <hex>
       Uniform: every party gets the same bytes.
     :challenge-context-hex-by-role {role <hex>}
       Per-party: required for identity-share binding proofs.

   On success:
     {:proofs {role {:verification-share-hex ... :proof-hex ...
                     :challenge-context-hex ...
                     :identity-pubkey-hex ... ; binding-mode only
                     :identity-signature-hex ...}}
      :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [share-handle challenge-context-hex challenge-context-hex-by-role
           binding-mode? deadline-ms chart-path]
    :or   {deadline-ms 30000
           chart-path  "../specs/executable/statechart-share-possession-proof.edn"}}]
  (assert share-handle "run-share-possession-proof-via-chart: :share-handle required")
  (assert (or challenge-context-hex challenge-context-hex-by-role)
          "run-share-possession-proof-via-chart: :challenge-context-hex or :challenge-context-hex-by-role required")
  (let [ceremony-id  (uuidv7/uuidv7)
        peers        (vec participants)
        ids          (select-keys participant-ids peers)
        peer-pubkeys (select-keys identity-pubkeys peers)
        ctx-for      (fn [me] (or (get challenge-context-hex-by-role me)
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
        build-result (fn [{:ceremony/keys [results]}]
                       {:proofs (into {}
                                      (for [[r m] results]
                                        [r (cond-> {:verification-share-hex (:result/verification-share-hex m)
                                                    :proof-hex              (:result/proof-hex m)
                                                    :challenge-context-hex  (ctx-for r)}
                                             binding-mode?
                                             (assoc :identity-pubkey-hex    (:result/identity-pubkey-hex m)
                                                    :identity-signature-hex (:result/identity-signature-hex m)))]))
                        :ceremony/id ceremony-id})
        domain-ctx   {:ceremony/id            ceremony-id
                      :ceremony/participants  peers
                      :ceremony/share-handle  share-handle
                      :ceremony/binding-mode? (boolean binding-mode?)}]
    (run-chart-fsm! orch peers chart-path domain-ctx make-begin build-result
                    deadline-ms)))

(defn run-keygen-via-chart
  "Chart-driven equivalent of ceremony/run-keygen. On success:
     {:public-key <hex>
      :share-handle <uuid>
      :handles {role <uuid>}
      :verification-shares {role <hex>}
      :ceremony/id <uuid>}"
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold deadline-ms chart-path]
    :or   {threshold 2
           deadline-ms 60000
           chart-path  "../specs/executable/statechart-keygen.edn"}}]
  (let [ceremony-id  (uuidv7/uuidv7)
        share-handle (uuidv7/uuidv7)
        peers        (vec participants)
        ids          (select-keys participant-ids peers)
        peer-pubkeys (select-keys identity-pubkeys peers)
        make-begin   (fn [me]
                       {:msg/type                 :ceremony/begin-keygen
                        :ceremony/id              ceremony-id
                        :ceremony/me              me
                        :ceremony/peers           peers
                        :ceremony/participant-ids ids
                        :ceremony/peer-pubkeys    peer-pubkeys
                        :ceremony/threshold       threshold
                        :ceremony/share-handle    share-handle})
        build-result (fn [state]
                       ;; :ceremony/public-key + :ceremony/verification-shares
                       ;; are populated by :action/keygen-consistency-check.
                       {:public-key          (:ceremony/public-key state)
                        :share-handle        share-handle
                        :handles             (into {} (for [r peers] [r share-handle]))
                        :verification-shares (:ceremony/verification-shares state)
                        :ceremony/id         ceremony-id})
        domain-ctx   {:ceremony/id           ceremony-id
                      :ceremony/participants peers
                      :ceremony/threshold    threshold
                      :ceremony/share-handle share-handle}]
    (run-chart-fsm! orch peers chart-path domain-ctx make-begin build-result
                    deadline-ms)))
