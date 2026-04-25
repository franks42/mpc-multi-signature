(ns mpc-multi-signature.orchestrator.core
  "REPL-facing entry. Spawns party subprocesses, exposes ceremony
   functions (keygen for Stage 1; sign and reshare in later stages),
   and shuts everything down cleanly."
  (:require [mpc-multi-signature.orchestrator.ceremony :as ceremony]
            [mpc-multi-signature.orchestrator.party-connection :as party]
            [mpc-multi-signature.orchestrator.telemetry :as telemetry]
            [taoensso.trove :as log]))

(def ^:private default-roles
  [:holder :figure :ic])

(defn- project-root
  "The working directory used when spawning party subprocesses. The
   orchestrator runs from `orchestrator/` (deps.edn lives there); the
   parties run from the project root, where bb.edn lives."
  []
  (-> (System/getProperty "user.dir")
      (java.io.File.)
      .getCanonicalFile
      .getParentFile
      .getCanonicalPath))

(defn start-orchestrator
  "Spawn one party subprocess per role and return an orchestrator
   handle:

     {:connections-by-role {:holder ..., :figure ..., :ic ...}
      :working-dir         <abs path>}

   `opts` (all optional):
     :roles        — vector of role keywords; defaults to [:holder :figure :ic]
     :working-dir  — absolute path to project root; auto-detected by default
     :bb-task      — bb task name to invoke for each party; defaults to \"null-party\""
  ([] (start-orchestrator {}))
  ([{:keys [roles working-dir bb-task]
     :or   {roles       default-roles
            bb-task     "null-party"}}]
   (telemetry/ensure-initialized!)
   (let [wd (or working-dir (project-root))
         connections-by-role
         (into {}
               (for [role roles]
                 [role (party/start! {:role role :working-dir wd :bb-task bb-task})]))]
     (log/log! {:level :info
                :id    :mpc-multi-signature.orchestrator.core/started
                :msg   "Orchestrator started"
                :data  {:roles (vec roles) :working-dir wd}})
     {:connections-by-role connections-by-role
      :working-dir         wd})))

(defn keygen
  "Run a keygen ceremony over the given participants. Returns the
   result map from ceremony/run-keygen."
  ([orch participants]
   (keygen orch participants {}))
  ([orch participants opts]
   (ceremony/run-keygen orch participants opts)))

(defn stop-orchestrator
  "Stop all party subprocesses. Returns a map of role -> exit code."
  [{:keys [connections-by-role]}]
  (let [exits (into {}
                    (for [[role conn] connections-by-role]
                      [role (party/stop! conn)]))]
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.core/stopped
               :msg   "Orchestrator stopped"
               :data  {:exits exits}})
    exits))
