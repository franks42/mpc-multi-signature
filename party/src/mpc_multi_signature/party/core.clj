(ns mpc-multi-signature.party.core
  "The party-bb wrapper. Identical for all three roles; --role flag
   selects the party. Spawns the crypto-core Rust subprocess and
   translates EDN (with the orchestrator) <-> JSON-Lines (with the
   Rust subprocess).

   EDN↔JSON translation rules per design doc Appendix B:
   - `:msg/type :ceremony/begin-X` ⇄ `\"msg_type\": \"begin_x\"`
     (namespace+name joined by `_`; hyphens become underscores)
   - Role/actor keywords ⇄ integer participant ids on the JSON side.
     The mapping is established from `:ceremony/peers` order in the
     begin message and held for the ceremony's duration.
   - UUIDs become strings on the JSON side; orchestrator side gets EDN
     `#uuid \"...\"`.
   - Binary protocol bodies stay base64 strings on both sides; this
     wrapper does not decode them.
   - Per-party file paths (shares, triples, presignatures) are
     computed locally from (role, handle, artifact-kind) — orchestrator
     supplies handles, bb wrapper supplies paths.

   Stage 4 scope: keygen + triples + presign + sign + reshare."
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [signet.key :as signet-key]
            [signet.session :as signet-session]
            [signet.sign :as signet-sign]
            [taoensso.timbre :as timbre]
            [taoensso.trove :as log]
            [taoensso.trove.timbre :as backend])
  (:import (java.io BufferedReader BufferedWriter PushbackReader)
           (java.lang ProcessBuilder ProcessBuilder$Redirect)))

;; ---- telemetry init ----

(defn- init-telemetry! [role]
  (timbre/merge-config!
   {:min-level :info
    :appenders {:println {:enabled? true
                          :fn (fn [data]
                                (binding [*out* *err*]
                                  (println (force (:output_ data)))
                                  (flush)))}}})
  (log/set-log-fn! (backend/get-log-fn))
  (log/log! {:level :info
             :id    :mpc-multi-signature.party.core/started
             :data  {:role role}}))

(defn- parse-args [args]
  (loop [acc {} [k v & more] args]
    (cond
      (nil? k) acc
      (= "--role" k) (recur (assoc acc :role (keyword v)) more)
      :else (recur acc (cons v more)))))

;; ---- per-party identity keypair ----
;;
;; Stage 5b.2: each party holds its own Ed25519 identity keypair. The
;; private key never leaves the bb wrapper; only the public key is
;; announced to the orchestrator at startup via a :party/identity
;; handshake message. Production placement; replaces the harness-only
;; orchestrator-side keypair generation we ran through Stage 5a.

(defn- bytes->hex [^bytes bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn- hex->bytes [^String s]
  (let [n   (quot (count s) 2)
        out (byte-array n)]
    (dotimes [i n]
      (aset out i (unchecked-byte (Integer/parseInt (subs s (* i 2) (+ (* i 2) 2)) 16))))
    out))

(defn- bytes->base64 [^bytes bs]
  (.encodeToString (java.util.Base64/getEncoder) bs))

(defn- base64->bytes [^String s]
  (.decode (java.util.Base64/getDecoder) s))

(defn- make-identity-keypair
  "Generate a fresh Ed25519 identity keypair for this bb wrapper. A
   future revision may add an env-var override for repeatable test
   setups; today we keep things minimal."
  []
  (signet-key/signing-keypair))

;; ---- per-ceremony Noise_KK pairwise sessions (Stage 5b.1) ----
;;
;; Forward-secret session layer between every pair of share-holders.
;; Per ceremony, this party runs one Noise_KK_25519_ChaChaPoly_SHA256
;; handshake with each peer (deterministic role: lower role-int
;; initiates). Once all sessions are established, crypto-core's
;; protocol_private and protocol_broadcast bodies are AEAD-wrapped
;; outbound and unwrapped inbound; the orchestrator routes opaque
;; ciphertext.

(defn- build-sessions
  "Build the initial pairwise handshake-state map: one entry per peer.

   `me`             — this party's role keyword.
   `peer-pubkeys`   — {role hex-pubkey} carried in the begin message;
                      includes me as well, which we filter out.
   `participant-ids`— {role int} canonical role↔id; used to pick
                      initiator vs responder per pair (lower id wins).
   `identity-kp`    — this party's long-term Ed25519 keypair.
   `ceremony-id`    — uuid; bound into each session as the Noise
                      prologue, so the same pair running two ceremonies
                      derives different session keys.

   Returns an atom keyed by peer-role, holding signet.session states."
  [me peer-pubkeys participant-ids identity-kp ceremony-id]
  (let [my-id    (get participant-ids me)
        prologue (.getBytes (str ceremony-id) "UTF-8")]
    (atom
     (into {}
           (for [[peer pubkey-hex] peer-pubkeys
                 :when             (not= peer me)
                 :let  [their-id   (get participant-ids peer)
                        remote-pub (signet-key/->Ed25519PublicKey
                                    :signet/ed25519-public-key
                                    :Ed25519
                                    (hex->bytes pubkey-hex))
                        i-am-init? (< my-id their-id)
                        builder    (if i-am-init?
                                     signet-session/initiator
                                     signet-session/responder)]]
             [peer (builder identity-kp remote-pub {:prologue prologue})])))))

(defn- session-write!
  "Atomically apply Noise write-message to the session with `peer`,
   returning the ciphertext bytes. Uses a volatile to extract the
   produced ciphertext from inside swap! while keeping the session
   update atomic. swap!'s retries are cheap and idempotent in
   transport mode (same key, same nonce, same plaintext → same ct)."
  [sessions peer ^bytes plaintext]
  (let [ct-vol (volatile! nil)]
    (swap! sessions update peer
           (fn [s]
             (let [[s' ct] (signet-session/write-message s plaintext)]
               (vreset! ct-vol ct)
               s')))
    @ct-vol))

(defn- session-read!
  "Atomically apply Noise read-message to the session with `peer`,
   returning the plaintext bytes. Same pattern as session-write!."
  [sessions peer ^bytes ciphertext]
  (let [pt-vol (volatile! nil)]
    (swap! sessions update peer
           (fn [s]
             (let [[s' pt] (signet-session/read-message s ciphertext)]
               (vreset! pt-vol pt)
               s')))
    @pt-vol))

(defn- send-private!
  "Helper: emit a :protocol/private EDN message to the orchestrator,
   carrying base64-encoded ciphertext for `to` peer."
  [out-writer me to ceremony-id ^bytes ct]
  (locking out-writer
    (.write ^java.io.Writer out-writer
            (pr-str {:msg/type      :protocol/private
                     :ceremony/id   ceremony-id
                     :protocol/from me
                     :protocol/to   to
                     :protocol/body (bytes->base64 ct)}))
    (.write ^java.io.Writer out-writer "\n")
    (.flush ^java.io.Writer out-writer)))

(defn- all-established?
  [sessions]
  (every? signet-session/established? (vals @sessions)))

(defn- do-handshakes!
  "Drive Noise_KK pairwise handshakes to completion before any
   crypto-core protocol traffic flows. Procedure:

   1. For each peer where I'm initiator, write Noise message 1
      (empty payload) and dispatch as :protocol/private to the
      orchestrator, which routes to that peer.
   2. Loop on inbound messages from the orchestrator. Each
      :protocol/deliver arriving during this phase is a Noise
      handshake message from the named sender:
        - If I'm responder for that peer: read msg 1, then write
          msg 2 in reply.
        - If I'm initiator: read msg 2, my session is now established.
   3. Continue until every peer's session reports established?.

   The same EDN message types (:protocol/private, :protocol/deliver)
   carry both Noise handshake traffic and post-handshake encrypted
   protocol traffic. The orchestrator does not distinguish: it just
   routes."
  [me sessions in-reader out-writer ceremony-id]
  ;; Fire opening handshake messages.
  (doseq [[peer s] @sessions
          :when    (= :initiator (:role s))]
    (let [ct (session-write! sessions peer (byte-array 0))]
      (send-private! out-writer me peer ceremony-id ct)))
  ;; Drive inbound until all sessions have completed Split().
  (loop []
    (when-not (all-established? sessions)
      (let [msg (try (edn/read {:eof ::eof} in-reader)
                     (catch Exception _e ::eof))]
        (cond
          (= ::eof msg)
          (throw (ex-info "EOF during Noise handshake" {:phase :handshake}))

          (= :ceremony/cancel (:msg/type msg))
          (throw (ex-info "Cancel during Noise handshake" {:phase :handshake}))

          (= :protocol/deliver (:msg/type msg))
          (let [from (:protocol/from msg)
                ct   (base64->bytes (:protocol/body msg))]
            (session-read! sessions from ct)
            ;; If this peer's session is responder-side and now has
            ;; pos=1 (msg 1 read but not yet established), produce
            ;; msg 2 in reply. The sole non-established post-read
            ;; case is the responder having just consumed msg 1.
            (when-not (signet-session/established? (get @sessions from))
              (let [ct2 (session-write! sessions from (byte-array 0))]
                (send-private! out-writer me from ceremony-id ct2))))

          :else
          (log/log! {:level :warn
                     :id    :mpc-multi-signature.party.core/unexpected-during-handshake
                     :data  {:msg-type (:msg/type msg)}}))
        (recur))))
  (log/log! {:level :info
             :id    :mpc-multi-signature.party.core/noise-handshakes-established
             :data  {:role me :peers (vec (keys @sessions))}}))

;; ---- per-party artifact paths ----

(defn- artifact-path
  "<project-root>/<role>/<kind>/<handle>.bin"
  [role kind handle-uuid]
  (-> (System/getProperty "user.dir")
      (java.io.File. (str (name role) "/" (name kind) "/" handle-uuid ".bin"))
      .getCanonicalPath))

;; ---- Rust subprocess ----

(defn- locate-crypto-core []
  (or (System/getenv "MPC_CRYPTO_CORE")
      (let [base (System/getProperty "user.dir")
            release (java.io.File. base "crypto-core/target/release/mpc-crypto-core")
            debug   (java.io.File. base "crypto-core/target/debug/mpc-crypto-core")]
        (.getCanonicalPath (if (.exists release) release debug)))))

(defn- spawn-crypto-core! [role]
  (let [bin (locate-crypto-core)
        pb  (doto (ProcessBuilder. [bin "--role" (name role)])
              (.redirectError ProcessBuilder$Redirect/INHERIT))]
    (log/log! {:level :info
               :id    :mpc-multi-signature.party.core/spawning
               :data  {:role role :bin bin}})
    (.start pb)))

;; ---- EDN ↔ JSON translation: begin-* messages ----

;; Each begin-X uses orchestrator-supplied :ceremony/participant-ids
;; (a {role int} map) for me/peers translation. This map is the
;; CANONICAL global role↔int registered at start-orchestrator time —
;; stable across all ceremonies so threshold-signatures shares remain
;; valid (they're bound to specific integer participant ids).

(defn- begin-keygen->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/share-handle :ceremony/participant-ids]}]
  {:msg_type    "begin_keygen"
   :ceremony_id (str id)
   :me          (get participant-ids me)
   :peers       (mapv participant-ids peers)
   :threshold   threshold
   :share_path  (artifact-path me "shares" share-handle)})

(defn- begin-triples->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/triple-handle :ceremony/participant-ids]}]
  {:msg_type    "begin_triples"
   :ceremony_id (str id)
   :me          (get participant-ids me)
   :peers       (mapv participant-ids peers)
   :threshold   threshold
   :triple_path (artifact-path me "triples" triple-handle)})

(defn- begin-presign->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/share-handle :ceremony/triple-handle :ceremony/presig-handle
           :ceremony/participant-ids]}]
  {:msg_type    "begin_presign"
   :ceremony_id (str id)
   :me          (get participant-ids me)
   :peers       (mapv participant-ids peers)
   :threshold   threshold
   :share_path  (artifact-path me "shares" share-handle)
   :triple_path (artifact-path me "triples" triple-handle)
   :presig_path (artifact-path me "presigs" presig-handle)})

(defn- begin-sign->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/coordinator :ceremony/share-handle :ceremony/presig-handle
           :ceremony/digest-hex :ceremony/participant-ids]}]
  {:msg_type    "begin_sign"
   :ceremony_id (str id)
   :me          (get participant-ids me)
   :peers       (mapv participant-ids peers)
   :threshold   threshold
   :coordinator (get participant-ids coordinator)
   :share_path  (artifact-path me "shares" share-handle)
   :presig_path (artifact-path me "presigs" presig-handle)
   :digest_hex  digest-hex})

(defn- begin-reshare->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/old-peers :ceremony/old-threshold
           :ceremony/new-peers :ceremony/new-threshold
           :ceremony/old-share-handle :ceremony/new-share-handle
           :ceremony/public-key-hex :ceremony/participant-ids]}]
  {:msg_type        "begin_reshare"
   :ceremony_id     (str id)
   :me              (get participant-ids me)
   :old_peers       (mapv participant-ids old-peers)
   :old_threshold   old-threshold
   :new_peers       (mapv participant-ids new-peers)
   :new_threshold   new-threshold
   :old_share_path  (when old-share-handle
                      (artifact-path me "shares" old-share-handle))
   :public_key_hex  public-key-hex
   :new_share_path  (artifact-path me "shares" new-share-handle)})

(defn- begin-share-proof->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/share-handle
           :ceremony/challenge-context-hex :ceremony/participant-ids]}]
  {:msg_type              "begin_share_proof"
   :ceremony_id           (str id)
   :me                    (get participant-ids me)
   :share_path            (artifact-path me "shares" share-handle)
   :challenge_context_hex challenge-context-hex})

(defn- begin->json
  "Dispatch on :msg/type to the appropriate translator."
  [msg]
  (case (:msg/type msg)
    :ceremony/begin-keygen      (begin-keygen->json msg)
    :ceremony/begin-triples     (begin-triples->json msg)
    :ceremony/begin-presign     (begin-presign->json msg)
    :ceremony/begin-sign        (begin-sign->json msg)
    :ceremony/begin-reshare     (begin-reshare->json msg)
    :ceremony/begin-share-proof (begin-share-proof->json msg)
    (throw (ex-info "Unknown begin-* message type" {:type (:msg/type msg)}))))

(defn- ceremony-participant-ids
  "Pull the canonical {role int} map from a begin-* message. All
   begin-* shapes carry it; we pluck consistently."
  [msg]
  (:ceremony/participant-ids msg))

(defn- deliver->json
  "`r->i` is the canonical {role int} map carried on every begin
   message — same map we use for me/peers translation."
  [r->i {:keys [:ceremony/id :protocol/from :protocol/body]}]
  {:msg_type    "protocol_deliver"
   :ceremony_id (str id)
   :from        (get r->i from)
   :body        body})

(defn- cancel->json [{:keys [:ceremony/id]}]
  {:msg_type    "cancel"
   :ceremony_id (str id)})

;; ---- JSON → EDN: outbound from Rust to orchestrator ----

(defn- json-result->edn-result
  "Translate a JSON result map (snake_case keys, leaf values) into an
   EDN result map (`:result/kebab-case` keys). Mechanical."
  [m]
  (into {}
        (for [[k v] m]
          [(keyword "result" (str/replace (name k) "_" "-")) v])))

;; ---- I/O glue ----

(defn- send-edn! [out form]
  (locking out
    (.write ^java.io.Writer out (pr-str form))
    (.write ^java.io.Writer out "\n")
    (.flush ^java.io.Writer out)))

(defn- send-json! [out m]
  (locking out
    (.write ^java.io.Writer out (json/generate-string m))
    (.write ^java.io.Writer out "\n")
    (.flush ^java.io.Writer out)))

(defn- augment-with-binding-signature
  "When the begin message had :ceremony/binding-mode? true, the bb
   wrapper signs the Schnorr proof bytes locally with its own Ed25519
   identity key and adds :result/identity-pubkey-hex and
   :result/identity-signature-hex to the ceremony-complete result.
   Welds this party's Ed25519 identity to the MPC share without ever
   exposing the private key to the orchestrator."
  [{:ceremony/keys [result] :as msg} identity-kp]
  (let [proof-bytes (hex->bytes (:result/proof-hex result))
        sig-bytes   (signet-sign/sign identity-kp proof-bytes)]
    (assoc msg :ceremony/result
           (assoc result
                  :result/identity-pubkey-hex    (bytes->hex (:x identity-kp))
                  :result/identity-signature-hex (bytes->hex sig-bytes)))))

(defn- spawn-rust-reader-thread!
  "Translates messages from crypto-core's stdout (JSON Lines) to the
   orchestrator (EDN). Stage 5b.1: protocol_private and
   protocol_broadcast bodies are AEAD-wrapped via the per-peer
   Noise_KK session before being forwarded; broadcast is fanned out
   to one private message per peer (one ciphertext per recipient,
   each authenticated to that pair)."
  [role i->r ceremony-id-uuid rust-stdout out done?
   {:keys [binding-mode? identity-kp sessions]}]
  (let [reader (BufferedReader. (java.io.InputStreamReader. rust-stdout))
        ;; Snapshot peers at thread start; the session keyset is
        ;; fixed for the ceremony's lifetime.
        peers  (vec (keys @sessions))]
    (doto (Thread. ^Runnable
           (fn []
             (try
               (loop []
                 (let [line (.readLine reader)]
                   (when line
                     (let [m        (json/parse-string line)
                           msg-type (get m "msg_type")]
                       (case msg-type
                         "protocol_private"
                         (let [from-role (get i->r (get m "from"))
                               to-role   (get i->r (get m "to"))
                               pt        (base64->bytes (get m "body"))
                               ct        (session-write! sessions to-role pt)]
                           (send-edn! out
                                      {:msg/type      :protocol/private
                                       :ceremony/id   ceremony-id-uuid
                                       :protocol/from from-role
                                       :protocol/to   to-role
                                       :protocol/body (bytes->base64 ct)}))

                         "protocol_broadcast"
                         ;; Fan out: one encrypted private per peer.
                         ;; Each ciphertext is bound (via the Noise
                         ;; session's AEAD tag) to a specific recipient.
                         (let [from-role (get i->r (get m "from"))
                               pt        (base64->bytes (get m "body"))]
                           (doseq [peer peers]
                             (let [ct (session-write! sessions peer pt)]
                               (send-edn! out
                                          {:msg/type      :protocol/private
                                           :ceremony/id   ceremony-id-uuid
                                           :protocol/from from-role
                                           :protocol/to   peer
                                           :protocol/body (bytes->base64 ct)}))))

                         "ceremony_complete"
                         (let [edn  {:msg/type        :ceremony/complete
                                     :ceremony/id     ceremony-id-uuid
                                     :ceremony/result (json-result->edn-result (get m "result"))}
                               edn  (if binding-mode?
                                      (augment-with-binding-signature edn identity-kp)
                                      edn)]
                           (send-edn! out edn)
                           (reset! done? true))

                         "ceremony_error"
                         (do (send-edn! out
                                        {:msg/type       :ceremony/error
                                         :ceremony/id    ceremony-id-uuid
                                         :ceremony/error {:category (get m "category")
                                                          :message  (get m "message")}})
                             (reset! done? true))

                         ;; Unknown msg type from crypto-core
                         (log/log! {:level :warn
                                    :id    :mpc-multi-signature.party.core/unknown-rust-msg-type
                                    :data  {:role role :msg-type msg-type}}))
                       (recur)))))
               (catch Exception e
                 (log/log! {:level :error
                            :id    :mpc-multi-signature.party.core/rust-reader-error
                            :error e
                            :data  {:role role}}))
               (finally
                 (reset! done? true))))
                   (str "rust-reader-" (name role)))
      (.setDaemon true)
      (.start))))

;; ---- per-ceremony state machine ----

(declare begin-types)

(defn- run-ceremony!
  "Run one ceremony to completion. Returns:
     nil          — orchestrator EOF or cancel;
     <begin-msg>  — orchestrator sent a begin-* message after this
                    ceremony finished (its Rust subprocess exited);
                    -main hands it to a fresh run-ceremony! invocation.

   Stage 5b.1 lifecycle:
   1. Build pairwise Noise_KK sessions from :ceremony/peer-pubkeys.
   2. Drive Noise handshakes via :protocol/private routing — these
      messages travel through the orchestrator like any other peer
      traffic; the orchestrator does not distinguish handshake from
      protocol bytes.
   3. Once all sessions are established, spawn crypto-core and start
      the protocol. Outbound protocol bodies are AEAD-wrapped under
      the recipient's session in the rust-reader thread; inbound
      :protocol/deliver bodies are unwrapped here before forwarding
      to crypto-core."
  [role identity-kp begin-msg in-reader out-writer]
  (let [r->i           (ceremony-participant-ids begin-msg)
        i->r           (into {} (map (fn [[k v]] [v k])) r->i)
        ceremony-id    (:ceremony/id begin-msg)
        peer-pubkeys   (:ceremony/peer-pubkeys begin-msg)
        binding-mode?  (and (= :ceremony/begin-share-proof (:msg/type begin-msg))
                            (boolean (:ceremony/binding-mode? begin-msg)))
        sessions       (build-sessions role peer-pubkeys r->i identity-kp ceremony-id)
        ;; Drive Noise handshakes before spawning crypto-core. This
        ;; reads :protocol/deliver messages from the orchestrator
        ;; and dispatches Noise handshake replies via
        ;; :protocol/private; once every peer's session is
        ;; established, the function returns.
        _              (do-handshakes! role sessions in-reader out-writer ceremony-id)
        rust-process   (spawn-crypto-core! role)
        rust-stdin     (BufferedWriter. (java.io.OutputStreamWriter.
                                         (.getOutputStream rust-process)))
        done?          (atom false)
        wait-and-log!  (fn []
                         (try (.close rust-stdin) (catch Exception _ nil))
                         (.waitFor rust-process)
                         (log/log! {:level :info
                                    :id    :mpc-multi-signature.party.core/ceremony-end
                                    :data  {:role role
                                            :exit-code (.exitValue rust-process)}}))]
    (spawn-rust-reader-thread! role i->r ceremony-id
                               (.getInputStream rust-process) out-writer done?
                               {:binding-mode? binding-mode?
                                :identity-kp   identity-kp
                                :sessions      sessions})
    (send-json! rust-stdin (begin->json begin-msg))
    (loop []
      (let [msg (try (edn/read {:eof ::eof} in-reader)
                     (catch Exception _e ::eof))]
        (cond
          (= ::eof msg)
          (do (wait-and-log!) nil)

          ;; A begin-* for the NEXT ceremony — this one's Rust
          ;; subprocess has finished; let -main pick it up.
          (begin-types (:msg/type msg))
          (do (wait-and-log!) msg)

          (= :protocol/deliver (:msg/type msg))
          (do (if @done?
                (log/log! {:level :debug
                           :id    :mpc-multi-signature.party.core/late-deliver-dropped
                           :data  {:role role
                                   :ceremony-id (:ceremony/id msg)
                                   :from (:protocol/from msg)}})
                (try
                  (let [from (:protocol/from msg)
                        ct   (base64->bytes (:protocol/body msg))
                        pt   (session-read! sessions from ct)
                        plain-msg (assoc msg :protocol/body (bytes->base64 pt))]
                    (send-json! rust-stdin (deliver->json r->i plain-msg)))
                  (catch java.io.IOException _e
                    (reset! done? true))))
              (recur))

          (= :ceremony/cancel (:msg/type msg))
          (do (try (send-json! rust-stdin (cancel->json msg))
                   (catch java.io.IOException _e nil))
              (wait-and-log!)
              nil)

          :else
          (do (log/log! {:level :warn
                         :id    :mpc-multi-signature.party.core/unexpected-orchestrator-msg
                         :data  {:role role :msg-type (:msg/type msg)}})
              (recur)))))))

;; ---- entry ----

(def ^:private begin-types
  #{:ceremony/begin-keygen :ceremony/begin-triples :ceremony/begin-presign
    :ceremony/begin-sign   :ceremony/begin-reshare :ceremony/begin-share-proof})

(defn- send-identity-handshake!
  "First message on stdout, before any ceremony is requested. Tells
   the orchestrator this party's role and identity public key. The
   orchestrator's start-orchestrator blocks until it has received one
   such message per role; private key stays in this process."
  [out-writer role identity-kp]
  (send-edn! out-writer
             {:msg/type           :party/identity
              :role               role
              :identity/pubkey-hex (bytes->hex (:x identity-kp))})
  (log/log! {:level :info
             :id    :mpc-multi-signature.party.core/identity-announced
             :data  {:role role
                     :identity-pubkey-hex (bytes->hex (:x identity-kp))}}))

(defn -main [& args]
  (let [{:keys [role]} (parse-args args)]
    (when-not role
      (binding [*out* *err*]
        (println "Usage: bb party --role <holder|figure|ic>"))
      (System/exit 1))
    (init-telemetry! role)
    (let [in-reader  (PushbackReader. *in*)
          out-writer *out*
          identity-kp (make-identity-keypair)]
      (send-identity-handshake! out-writer role identity-kp)
      (loop [pending nil]
        (let [msg (or pending
                      (try (edn/read {:eof ::eof} in-reader)
                           (catch Exception _e ::eof)))]
          (cond
            (= ::eof msg)
            (log/log! {:level :info
                       :id    :mpc-multi-signature.party.core/eof
                       :data  {:role role}})

            (begin-types (:msg/type msg))
            ;; run-ceremony! returns either nil (clean end) or the
            ;; next begin-* message; we chain on whichever it returned.
            (recur (run-ceremony! role identity-kp msg in-reader out-writer))

            :else
            (do (log/log! {:level :warn
                           :id    :mpc-multi-signature.party.core/pre-ceremony-msg
                           :data  {:role role :msg-type (:msg/type msg)}})
                (recur nil))))))))
