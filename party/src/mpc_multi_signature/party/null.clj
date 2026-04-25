(ns mpc-multi-signature.party.null
  "Stage 1 null party stub.

   Reads EDN messages from stdin (one form per line), dispatches on
   :msg/type, and writes EDN responses to stdout. No real cryptography:
   :ceremony/begin-keygen produces a placeholder result derived from the
   ceremony id so all parties agree on the public-key for the
   orchestrator's keygen consistency check.

   Trove logs go to stderr; stdout is reserved for EDN protocol
   traffic. Exits cleanly on EOF."
  (:require [clojure.edn :as edn]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [taoensso.timbre :as timbre]
            [taoensso.trove :as log]
            [taoensso.trove.timbre :as backend])
  (:import (java.io PushbackReader)))

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
             :id    :mpc-multi-signature.party.null/started
             :msg   "Null party started"
             :data  {:role role}}))

(defn- parse-args [args]
  (loop [acc {} [k v & more] args]
    (cond
      (nil? k) acc
      (= "--role" k) (recur (assoc acc :role (keyword v)) more)
      :else (recur acc (cons v more)))))

(defn- placeholder-public-key
  "All parties derive the public-key string from the ceremony id, so the
   orchestrator's keygen consistency check passes trivially."
  [ceremony-id]
  (str "0x04stub-pk-" ceremony-id))

(defn- handle-begin-keygen [role msg]
  (let [ceremony-id (:ceremony/id msg)]
    (log/log! {:level :info
               :id    :mpc-multi-signature.party.null/begin-keygen
               :msg   "Received begin-keygen"
               :data  {:role role :ceremony-id ceremony-id}})
    {:msg/type        :ceremony/complete
     :ceremony/id     ceremony-id
     :ceremony/result {:result/handle     (uuidv7/uuidv7)
                       :result/public-key (placeholder-public-key ceremony-id)
                       :result/signature  nil}}))

(defn- handle-cancel [role msg]
  (log/log! {:level :warn
             :id    :mpc-multi-signature.party.null/cancel
             :msg   "Received cancel"
             :data  {:role role :ceremony-id (:ceremony/id msg)}})
  nil)

(defn- handle-message [role msg]
  (case (:msg/type msg)
    :ceremony/begin-keygen (handle-begin-keygen role msg)
    :ceremony/cancel        (handle-cancel role msg)
    (do (log/log! {:level :warn
                   :id    :mpc-multi-signature.party.null/unknown-message
                   :msg   "Unknown message type"
                   :data  {:role role :msg-type (:msg/type msg)}})
        nil)))

(defn- send! [msg]
  (println (pr-str msg))
  (flush))

(defn- read-loop! [role]
  (let [reader (PushbackReader. *in*)]
    (loop []
      (let [msg (try
                  (edn/read {:eof ::eof} reader)
                  (catch Exception e
                    (log/log! {:level :error
                               :id    :mpc-multi-signature.party.null/read-error
                               :error e
                               :data  {:role role}})
                    ::eof))]
        (cond
          (= ::eof msg)
          (log/log! {:level :info
                     :id    :mpc-multi-signature.party.null/eof
                     :data  {:role role}})

          :else
          (do
            (when-let [response (handle-message role msg)]
              (send! response))
            (recur)))))))

(defn -main [& args]
  (let [{:keys [role]} (parse-args args)]
    (when-not role
      (binding [*out* *err*]
        (println "Usage: bb null-party --role <holder|figure|ic>"))
      (System/exit 1))
    (init-telemetry! role)
    (read-loop! role)))
