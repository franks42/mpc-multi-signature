(ns mpc-multi-signature.orchestrator.telemetry
  "Trove + Timbre bootstrap for the orchestrator.

   Routes logs to stderr so that any future stdout-bound EDN/JSON
   transports stay clean. Mirrors the bb-mcp-server pattern."
  (:require [taoensso.timbre :as timbre]
            [taoensso.trove :as log]
            [taoensso.trove.timbre :as backend]))

(defonce ^:private initialized? (atom false))

(defn- stderr-appender []
  {:enabled? true
   :fn (fn [data]
         (binding [*out* *err*]
           (println (force (:output_ data)))
           (flush)))})

(defn init!
  ([] (init! {}))
  ([{:keys [level] :or {level :info}}]
   (timbre/merge-config!
    {:min-level level
     :appenders {:println (stderr-appender)}})
   (log/set-log-fn! (backend/get-log-fn))
   (reset! initialized? true)
   (log/log! {:level :info
              :id    :mpc-multi-signature.orchestrator.telemetry/initialized
              :msg   "Orchestrator telemetry initialized"
              :data  {:level level}})
   :initialized))

(defn ensure-initialized! []
  (when-not @initialized?
    (init!)))
