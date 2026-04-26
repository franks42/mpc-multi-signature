(ns mpc-multi-signature.party.core
  "The party-bb wrapper. Identical for all three roles; --role flag
   selects the party. Spawns the crypto-core Rust subprocess and
   translates EDN (with the orchestrator) <-> JSON-Lines (with the
   Rust subprocess).

   EDN↔JSON translation rules per design doc Appendix B:
   - `:msg/type :ceremony/begin-keygen` ⇄ `\"msg_type\": \"begin_keygen\"`
     (namespace+name joined by `_`; hyphens become underscores)
   - Role/actor keywords ⇄ integer participant ids on the JSON side.
     The mapping is established from `:ceremony/peers` order in the
     begin-keygen message and held for the ceremony's duration.
   - UUIDs become strings on the JSON side; orchestrator side gets EDN
     `#uuid \"...\"`.
   - Binary protocol bodies stay base64 strings on both sides; this
     wrapper does not decode them.

   Stage 3 scope: keygen end-to-end with real shares and persistence.
   Sign and reshare arrive in later stages."
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [taoensso.timbre :as timbre]
            [taoensso.trove :as log]
            [taoensso.trove.timbre :as backend])
  (:import (java.io BufferedReader BufferedWriter PushbackReader)
           (java.lang ProcessBuilder ProcessBuilder$Redirect)))

;; ---- telemetry init (mirrors null.clj) ----

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

;; ---- per-ceremony role-id mapping ----

(defn- role->id-map [peers]
  (into {} (map-indexed (fn [i r] [r i]) peers)))

(defn- id->role-map [peers]
  (into {} (map-indexed (fn [i r] [i r]) peers)))

;; ---- Rust subprocess management ----

(defn- locate-crypto-core
  "Find the mpc-crypto-core binary. Prefers release; falls back to debug.
   MPC_CRYPTO_CORE env var overrides both."
  []
  (or (System/getenv "MPC_CRYPTO_CORE")
      (let [base   (System/getProperty "user.dir")
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

;; ---- JSON <-> EDN translation ----

(defn- share-path
  "Per-party share file path: <project-root>/<role>/shares/<handle>.bin.
   Per the design doc, handle namespace is per-party."
  [role handle-uuid]
  (-> (System/getProperty "user.dir")
      (java.io.File. (str (name role) "/shares/" handle-uuid ".bin"))
      .getCanonicalPath))

(defn- begin->json
  "Translate a :ceremony/begin-keygen EDN map into the JSON map the
   Rust binary expects. Uses `peers` (a vector of role keywords) to
   map `me` and the integer-indexed peer list. Adds the per-party
   share file path that the Rust binary writes its KeygenOutput to."
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold]}
   handle-uuid]
  (let [r->i (role->id-map peers)]
    {:msg_type    "begin_keygen"
     :ceremony_id (str id)
     :me          (get r->i me)
     :peers       (vec (range (count peers)))
     :threshold   threshold
     :share_path  (share-path me handle-uuid)}))

(defn- deliver->json
  "Translate a :protocol/deliver EDN map (from orchestrator) into the
   JSON `protocol_deliver` for the Rust binary."
  [r->i {:keys [:ceremony/id :protocol/from :protocol/body]}]
  {:msg_type    "protocol_deliver"
   :ceremony_id (str id)
   :from        (get r->i from)
   :body        body})

(defn- cancel->json [{:keys [:ceremony/id]}]
  {:msg_type    "cancel"
   :ceremony_id (str id)})

(defn- json->edn-out
  "Translate one JSON map (received from Rust stdout) into the EDN
   message to forward to the orchestrator. Returns nil for unknown
   shapes."
  [i->r ceremony-id-uuid handle-uuid m]
  (case (get m "msg_type")
    "protocol_broadcast"
    {:msg/type      :protocol/broadcast
     :ceremony/id   ceremony-id-uuid
     :protocol/from (get i->r (get m "from"))
     :protocol/body (get m "body")}

    "protocol_private"
    {:msg/type      :protocol/private
     :ceremony/id   ceremony-id-uuid
     :protocol/from (get i->r (get m "from"))
     :protocol/to   (get i->r (get m "to"))
     :protocol/body (get m "body")}

    "ceremony_complete"
    {:msg/type        :ceremony/complete
     :ceremony/id     ceremony-id-uuid
     :ceremony/result {:result/handle      handle-uuid
                       :result/public-key  (get m "public_key_hex")
                       :result/fingerprint (get m "share_fingerprint")
                       :result/signature   nil}}

    "ceremony_error"
    {:msg/type        :ceremony/error
     :ceremony/id     ceremony-id-uuid
     :ceremony/error  {:category (get m "category")
                       :message  (get m "message")}}

    nil))

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

(defn- spawn-rust-reader-thread!
  "Read JSON-Lines from the Rust subprocess stdout, translate to EDN,
   forward to the orchestrator (`out` = *out*). Sets `done?` when the
   Rust process emits ceremony_complete or ceremony_error or its
   stdout closes — after which the main loop drops late-arriving
   :protocol/deliver messages per the chart's
   :late-protocol-message-after-final cross-cutting rule."
  [role i->r ceremony-id-uuid handle-uuid rust-stdout out done?]
  (let [reader (BufferedReader. (java.io.InputStreamReader. rust-stdout))]
    (doto (Thread. ^Runnable
           (fn []
             (try
               (loop []
                 (let [line (.readLine reader)]
                   (when line
                     (let [m   (json/parse-string line)
                           edn (json->edn-out i->r ceremony-id-uuid handle-uuid m)]
                       (when edn
                         (send-edn! out edn))
                       (when (#{"ceremony_complete" "ceremony_error"} (get m "msg_type"))
                         (reset! done? true))
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

(defn- run-ceremony! [role begin-msg in-reader out-writer]
  (let [peers          (:ceremony/peers begin-msg)
        r->i           (role->id-map peers)
        i->r           (id->role-map peers)
        ceremony-id    (:ceremony/id begin-msg)
        handle-uuid    (uuidv7/uuidv7)
        rust-process   (spawn-crypto-core! role)
        rust-stdin     (BufferedWriter. (java.io.OutputStreamWriter.
                                         (.getOutputStream rust-process)))
        done?          (atom false)]
    (spawn-rust-reader-thread! role i->r ceremony-id handle-uuid
                               (.getInputStream rust-process) out-writer done?)
    ;; Send begin to Rust.
    (send-json! rust-stdin (begin->json begin-msg handle-uuid))
    ;; Pump orchestrator stdin -> Rust stdin until EOF or cancel.
    (loop []
      (let [msg (try (edn/read {:eof ::eof} in-reader)
                     (catch Exception _e ::eof))]
        (cond
          (= ::eof msg)
          (do (try (.close rust-stdin) (catch Exception _ nil))
              (.waitFor rust-process)
              (log/log! {:level :info
                         :id    :mpc-multi-signature.party.core/ceremony-end
                         :data  {:role role :exit-code (.exitValue rust-process)}}))

          (= :protocol/deliver (:msg/type msg))
          (do (if @done?
                ;; Late-arriving protocol message after this party's
                ;; ceremony already concluded — drop silently.
                (log/log! {:level :debug
                           :id    :mpc-multi-signature.party.core/late-deliver-dropped
                           :data  {:role role
                                   :ceremony-id (:ceremony/id msg)
                                   :from (:protocol/from msg)}})
                (try (send-json! rust-stdin (deliver->json r->i msg))
                     (catch java.io.IOException _e
                       ;; Race: Rust exited between @done? check and
                       ;; the write. Treat as late-and-dropped.
                       (reset! done? true))))
              (recur))

          (= :ceremony/cancel (:msg/type msg))
          (do (try (send-json! rust-stdin (cancel->json msg))
                   (catch java.io.IOException _e nil))
              (try (.close rust-stdin) (catch Exception _ nil))
              (.waitFor rust-process))

          :else
          (do (log/log! {:level :warn
                         :id    :mpc-multi-signature.party.core/unexpected-orchestrator-msg
                         :data  {:role role :msg-type (:msg/type msg)}})
              (recur)))))))

;; ---- entry ----

(defn -main [& args]
  (let [{:keys [role]} (parse-args args)]
    (when-not role
      (binding [*out* *err*]
        (println "Usage: bb party --role <holder|figure|ic>"))
      (System/exit 1))
    (init-telemetry! role)
    (let [in-reader  (PushbackReader. *in*)
          out-writer *out*]
      (loop []
        (let [msg (try (edn/read {:eof ::eof} in-reader)
                       (catch Exception _e ::eof))]
          (cond
            (= ::eof msg)
            (log/log! {:level :info
                       :id    :mpc-multi-signature.party.core/eof
                       :data  {:role role}})

            (= :ceremony/begin-keygen (:msg/type msg))
            (do (run-ceremony! role msg in-reader out-writer)
                (recur))

            :else
            (do (log/log! {:level :warn
                           :id    :mpc-multi-signature.party.core/pre-ceremony-msg
                           :data  {:role role :msg-type (:msg/type msg)}})
                (recur))))))))
