(ns mpc-multi-signature.orchestrator.party-connection
  "Spawns a party as a bb subprocess and exposes EDN send/receive over
   its stdio. One reader thread per connection feeds inbound forms onto
   a core.async channel; outbound is a synchronous write to the
   subprocess's stdin.

   The subprocess is `bb <bb-task> --role <role>` invoked in the
   project's working directory; default task is \"party\"."
  (:require [clojure.core.async :as a]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [taoensso.trove :as log])
  (:import (java.io BufferedWriter PushbackReader)
           (java.lang ProcessBuilder ProcessBuilder$Redirect)))

(defn- start-reader-thread!
  "Reads EDN forms from the subprocess stdout and puts them on `inbound`.
   Closes `inbound` on EOF or read error."
  [role stdout-stream inbound]
  (let [reader (PushbackReader. (io/reader stdout-stream))]
    (doto (Thread. ^Runnable
           (fn []
             (try
               (loop []
                 (let [form (edn/read {:eof ::eof} reader)]
                   (cond
                     (= ::eof form)
                     (log/log! {:level :info
                                :id    :mpc-multi-signature.orchestrator.party-connection/eof
                                :data  {:role role}})

                     :else
                     (do (a/>!! inbound form)
                         (recur)))))
               (catch Exception e
                 (log/log! {:level :error
                            :id    :mpc-multi-signature.orchestrator.party-connection/reader-error
                            :error e
                            :data  {:role role}}))
               (finally
                 (a/close! inbound))))
                   (str "party-reader-" (name role)))
      (.setDaemon true)
      (.start))))

(defn start!
  "Spawn `bb <bb-task> --role <role>` in `working-dir`. Returns a
   connection map: {:role :process :inbound :writer}."
  [{:keys [role working-dir bb-task]
    :or   {bb-task "party"}}]
  (let [pb       (doto (ProcessBuilder. ["bb" bb-task "--role" (name role)])
                   (.directory (io/file working-dir))
                   (.redirectError ProcessBuilder$Redirect/INHERIT))
        process  (.start pb)
        writer   (BufferedWriter. (io/writer (.getOutputStream process)))
        inbound  (a/chan 16)]
    (start-reader-thread! role (.getInputStream process) inbound)
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.party-connection/started
               :msg   "Party subprocess started"
               :data  {:role role :pid (.pid process)}})
    {:role    role
     :process process
     :inbound inbound
     :writer  writer}))

(defn send!
  "Write one EDN form to the party's stdin and flush."
  [{:keys [role ^BufferedWriter writer]} form]
  (.write writer (pr-str form))
  (.newLine writer)
  (.flush writer)
  (log/log! {:level :debug
             :id    :mpc-multi-signature.orchestrator.party-connection/sent
             :data  {:role role :msg-type (:msg/type form)}}))

(defn stop!
  "Close stdin (signals EOF to the party) and wait briefly for exit.
   Returns the exit code, or nil on timeout."
  [{:keys [role ^BufferedWriter writer process]}]
  (try (.close writer) (catch Exception _ nil))
  (let [exited? (.waitFor process 2 java.util.concurrent.TimeUnit/SECONDS)
        code    (when exited? (.exitValue process))]
    (when-not exited?
      (.destroy process)
      (log/log! {:level :warn
                 :id    :mpc-multi-signature.orchestrator.party-connection/forced-stop
                 :data  {:role role}}))
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.party-connection/stopped
               :data  {:role role :exit-code code}})
    code))
