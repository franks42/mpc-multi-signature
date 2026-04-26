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
  "Statechart action :action/send-begin-to-all-participants. For Stage 1
   keygen: emit :ceremony/begin-keygen to each participant connection."
  [connections-by-role ceremony-id participants threshold]
  (doseq [me participants
          :let [conn (get connections-by-role me)]]
    (party/send! conn
                 {:msg/type            :ceremony/begin-keygen
                  :ceremony/id         ceremony-id
                  :ceremony/me         me
                  :ceremony/peers      (vec participants)
                  :ceremony/threshold  threshold
                  :ceremony/scheme     :ecdsa/secp256k1-ot-based})))

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
   :result/public-key; {:passed? false :reason ...} otherwise."
  [results]
  (let [pks (into #{} (map :result/public-key) (vals results))]
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

(defn run-keygen
  "Drive a single keygen ceremony to completion. Returns a result map:

     {:public-key   <string>
      :handles      {role <uuid> ...}
      :ceremony/id  <uuid>}

   on success, or:

     {:error <reason-keyword> ...}

   on failure. Synchronous from the caller's perspective; internally
   uses core.async to wait on multiple inbound channels."
  [{:keys [connections-by-role]} participants {:keys [threshold deadline-ms]
                                               :or   {threshold 2 deadline-ms 5000}}]
  (let [ceremony-id (uuidv7/uuidv7)]
    (transition! ceremony-id :state/pending :state/starting)
    (send-begin-to-all! connections-by-role ceremony-id participants threshold)

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
              {:keys [passed? public-key reason] :as check}
              (keygen-consistency-check results)]
          (if passed?
            (let [handles (into {} (map (fn [[r m]] [r (:result/handle m)])) results)
                  result  {:public-key  public-key
                           :handles     handles
                           :ceremony/id ceremony-id}]
              (transition! ceremony-id :state/finalizing :state/complete)
              (log/log! {:level :info
                         :id    :mpc-multi-signature.orchestrator.ceremony/complete
                         :msg   "Ceremony complete"
                         :data  {:ceremony-id ceremony-id
                                 :public-key  public-key
                                 :handles     handles}})
              result)
            (do
              (transition! ceremony-id :state/finalizing :state/aborting)
              (send-cancel-to-all! connections-by-role participants ceremony-id reason)
              (transition! ceremony-id :state/aborting :state/failed)
              (log/log! {:level :error
                         :id    :mpc-multi-signature.orchestrator.ceremony/finalization-failed
                         :data  {:ceremony-id ceremony-id :check check}})
              {:error reason :ceremony/id ceremony-id :details check})))))))
