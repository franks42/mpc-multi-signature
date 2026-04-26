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

;; ---- per-ceremony role-id mapping ----

(defn- role->id-map [peers]
  (into {} (map-indexed (fn [i r] [r i]) peers)))

(defn- id->role-map [peers]
  (into {} (map-indexed (fn [i r] [i r]) peers)))

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

(defn- begin-keygen->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/share-handle]}]
  (let [r->i (role->id-map peers)]
    {:msg_type    "begin_keygen"
     :ceremony_id (str id)
     :me          (get r->i me)
     :peers       (vec (range (count peers)))
     :threshold   threshold
     :share_path  (artifact-path me "shares" share-handle)}))

(defn- begin-triples->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/triple-handle]}]
  (let [r->i (role->id-map peers)]
    {:msg_type    "begin_triples"
     :ceremony_id (str id)
     :me          (get r->i me)
     :peers       (vec (range (count peers)))
     :threshold   threshold
     :triple_path (artifact-path me "triples" triple-handle)}))

(defn- begin-presign->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/share-handle :ceremony/triple-handle :ceremony/presig-handle]}]
  (let [r->i (role->id-map peers)]
    {:msg_type    "begin_presign"
     :ceremony_id (str id)
     :me          (get r->i me)
     :peers       (vec (range (count peers)))
     :threshold   threshold
     :share_path  (artifact-path me "shares" share-handle)
     :triple_path (artifact-path me "triples" triple-handle)
     :presig_path (artifact-path me "presigs" presig-handle)}))

(defn- begin-sign->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/peers :ceremony/threshold
           :ceremony/coordinator :ceremony/share-handle :ceremony/presig-handle
           :ceremony/digest-hex]}]
  (let [r->i (role->id-map peers)]
    {:msg_type    "begin_sign"
     :ceremony_id (str id)
     :me          (get r->i me)
     :peers       (vec (range (count peers)))
     :threshold   threshold
     :coordinator (get r->i coordinator)
     :share_path  (artifact-path me "shares" share-handle)
     :presig_path (artifact-path me "presigs" presig-handle)
     :digest_hex  digest-hex}))

(defn- begin-reshare->json
  [{:keys [:ceremony/id :ceremony/me :ceremony/old-peers :ceremony/old-threshold
           :ceremony/new-peers :ceremony/new-threshold
           :ceremony/old-share-handle :ceremony/new-share-handle
           :ceremony/public-key-hex]}]
  ;; Both old and new participant lists need a shared integer-id space;
  ;; we use the union, with new-peers taking precedence for duplicate
  ;; roles. The Rust side validates internally.
  (let [union   (vec (distinct (concat old-peers new-peers)))
        r->i    (role->id-map union)
        old-int (mapv #(get r->i %) old-peers)
        new-int (mapv #(get r->i %) new-peers)]
    {:msg_type        "begin_reshare"
     :ceremony_id     (str id)
     :me              (get r->i me)
     :old_peers       old-int
     :old_threshold   old-threshold
     :new_peers       new-int
     :new_threshold   new-threshold
     :old_share_path  (when old-share-handle
                        (artifact-path me "shares" old-share-handle))
     :public_key_hex  public-key-hex
     :new_share_path  (artifact-path me "shares" new-share-handle)}))

(defn- begin->json
  "Dispatch on :msg/type to the appropriate translator."
  [msg]
  (case (:msg/type msg)
    :ceremony/begin-keygen   (begin-keygen->json msg)
    :ceremony/begin-triples  (begin-triples->json msg)
    :ceremony/begin-presign  (begin-presign->json msg)
    :ceremony/begin-sign     (begin-sign->json msg)
    :ceremony/begin-reshare  (begin-reshare->json msg)
    (throw (ex-info "Unknown begin-* message type" {:type (:msg/type msg)}))))

(defn- begin-msg-peers
  "Return the role-keyword peer list from a begin message — used to
   build the role↔id mapping for the rest of the ceremony's messages.
   For begin-reshare the ceremony's working participant set is the
   new-peers (those who emit/receive protocol messages)."
  [msg]
  (case (:msg/type msg)
    :ceremony/begin-reshare (vec (distinct (concat (:ceremony/old-peers msg)
                                                   (:ceremony/new-peers msg))))
    (:ceremony/peers msg)))

(defn- deliver->json
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

(defn- json->edn-out
  [i->r ceremony-id-uuid m]
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
     :ceremony/result (json-result->edn-result (get m "result"))}

    "ceremony_error"
    {:msg/type       :ceremony/error
     :ceremony/id    ceremony-id-uuid
     :ceremony/error {:category (get m "category")
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
  [role i->r ceremony-id-uuid rust-stdout out done?]
  (let [reader (BufferedReader. (java.io.InputStreamReader. rust-stdout))]
    (doto (Thread. ^Runnable
           (fn []
             (try
               (loop []
                 (let [line (.readLine reader)]
                   (when line
                     (let [m   (json/parse-string line)
                           edn (json->edn-out i->r ceremony-id-uuid m)]
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

(declare begin-types)

(defn- run-ceremony!
  "Run one ceremony to completion. Returns:
     nil          — orchestrator EOF or cancel;
     <begin-msg>  — orchestrator sent a begin-* message after this
                    ceremony finished (its Rust subprocess exited);
                    -main hands it to a fresh run-ceremony! invocation."
  [role begin-msg in-reader out-writer]
  (let [peers          (begin-msg-peers begin-msg)
        r->i           (role->id-map peers)
        i->r           (id->role-map peers)
        ceremony-id    (:ceremony/id begin-msg)
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
                               (.getInputStream rust-process) out-writer done?)
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
                (try (send-json! rust-stdin (deliver->json r->i msg))
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
    :ceremony/begin-sign   :ceremony/begin-reshare})

(defn -main [& args]
  (let [{:keys [role]} (parse-args args)]
    (when-not role
      (binding [*out* *err*]
        (println "Usage: bb party --role <holder|figure|ic>"))
      (System/exit 1))
    (init-telemetry! role)
    (let [in-reader  (PushbackReader. *in*)
          out-writer *out*]
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
            (recur (run-ceremony! role msg in-reader out-writer))

            :else
            (do (log/log! {:level :warn
                           :id    :mpc-multi-signature.party.core/pre-ceremony-msg
                           :data  {:role role :msg-type (:msg/type msg)}})
                (recur nil))))))))
