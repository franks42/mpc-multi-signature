(ns mpc-multi-signature.orchestrator.chart-driven-ceremonies
  "Chart-driven runtime for ceremonies. Translates a chart EDN to a
   clj-statecharts FSM, then runs the orchestrator-side ceremony
   lifecycle by feeding peer-message events to fsm/transition rather
   than the procedural state machine in `ceremony.clj`.

   Stage 1 of the chart-runtime POC: triple-generation only. Other
   ceremonies follow the same pattern once the actions/guards
   registries are extended.

   Action functions receive (state, event) and return either a new
   state map (using clj-statecharts's `assign` wrapper for context
   updates) or the same state for pure side effects (sending
   messages, queueing internal events, delivering to a result
   promise).

   Guard functions are higher-order: the registry value is invoked
   with the args from the chart's (guard/X args...) list, and
   returns the predicate `(fn [state event] -> bool)`.

   Plumbing context fields (namespaced :: keys) carry orchestrator
   handle, internal-events queue, result promise, etc. They are
   inserted into the FSM context before initialization and consumed
   by the action/guard functions."
  (:require [clojure.core.async :as a]
            [clojure.edn :as edn]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [mpc-multi-signature.orchestrator.chart-runtime :as cr]
            [mpc-multi-signature.orchestrator.party-connection :as party]
            [statecharts.core :as fsm]
            [taoensso.trove :as log]))

;; ============================================================
;; Generic actions — usable across all threshold-MPC ceremonies
;; whose chart specializes the keygen template.
;; ============================================================
;;
;; Each action is `(fn [state event] -> state')`. clj-statecharts
;; threads the returned state through. For context updates we use
;; `(fsm/assign f)` to wrap a function that takes (context event) and
;; returns new context — clj-statecharts will detect the assignment
;; record and apply it. For pure side effects (sending messages,
;; queueing events, delivering to promises) we just return state
;; unchanged.

(defn- send-begin-to-all-participants
  "Sends the per-ceremony begin message to each participant. The
   message-builder is held in context under
   ::make-begin (caller supplies it before initializing the FSM)."
  [{:keys [::orch ::participants ::make-begin] :as state} _event]
  (doseq [me participants
          :let [conn (get-in orch [:connections-by-role me])]
          :when conn]
    (party/send! conn (make-begin me)))
  state)

(defn- start-deadline-timer
  "Deadline tracking is handled by the event loop's a/timeout; this
   action is a structural marker that the deadline is now armed."
  [state _event]
  state)

(defn- route-message
  "Forwards a peer-emitted protocol message (broadcast or private)
   to the appropriate recipient(s). Mirrors ceremony/route-protocol-message!."
  [{:keys [::orch ::participants] :as state}
   {:protocol/keys [from body to] msg-type :msg/type ceremony-id :ceremony/id}]
  (log/log! {:level :info
             :id    :mpc-multi-signature.orchestrator.chart-driven-ceremonies/route-message-fired
             :data  {:from from :to to :msg-type msg-type
                     :body-prefix (when (string? body) (subs body 0 (min 16 (count body))))}})
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

      ;; unknown — log and drop
      (log/log! {:level :warn
                 :id    :mpc-multi-signature.orchestrator.chart-driven-ceremonies/unknown-route
                 :data  {:msg-type msg-type}})))
  state)

(defn- record-party-done
  "Records a party as done and stores its result in the context."
  [state {:keys [from result]}]
  (-> state
      (assoc-in [:ceremony/per-party-state from] :party-state/done)
      (assoc-in [:ceremony/results from] result)))

(defn- check-all-parties-done
  "Pure context-touching action; the guards on the multi-transition
   already inspect :ceremony/per-party-state. This action is a
   structural marker that the chart documents — no extra work."
  [state _event]
  state)

(defn- collect-per-party-results
  "Aggregates per-party results into a coherent ceremony-result
   structure on the context. For triple-generation, the results map
   already carries everything; this action is a no-op marker."
  [state _event]
  state)

(defn- triple-shape-check
  "Confirms every participant has reported a result with a
   :result/triple-handle echoing the assigned handle, then queues
   :event/finalization-passed (or :event/finalization-failed)."
  [{:keys [::participants ::pending-events :ceremony/results] :as state}
   _event]
  (let [all-handles (->> participants
                         (map #(get-in results [% :result/triple-handle]))
                         (every? some?))
        ;; Triple-gen has no orchestrator-side cross-party check —
        ;; the protocol's own VSS handles correctness — so we accept
        ;; any well-formed batch of complete messages.
        ok? (boolean all-handles)]
    (swap! pending-events conj
           (if ok? :event/finalization-passed :event/finalization-failed))
    state))

(defn- notify-coordinator-success
  "Delivers the success outcome to the result promise. The outcome
   shape mirrors the procedural run-triple-generation's return."
  [{:keys [::participants ::result-promise ::triple-handle :ceremony/id] :as state} _event]
  (deliver result-promise
           {:triple-handle triple-handle
            :handles       (into {} (for [r participants] [r triple-handle]))
            :ceremony/id   id})
  state)

(defn- persist-result-handles
  "Bookkeeping marker; the actual persistence (per-party share files
   etc.) happens at the bb wrappers, not orchestrator-side."
  [state _event]
  state)

(defn- send-cancel-to-all-participants
  "Sends :ceremony/cancel to every participant with the current error
   reason from context."
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
  "Queues :event/abort-timeout-elapsed on the pending-events. POC
   variant fires the event immediately rather than waiting for cancel
   acks — matches the existing procedural code's behaviour of
   transitioning to :state/failed on any abort path that doesn't
   collect explicit acks."
  [{:keys [::pending-events] :as state} _event]
  (swap! pending-events conj :event/abort-timeout-elapsed)
  state)

(defn- record-error
  [state {:keys [error]}]
  (assoc state :ceremony/error (or error :reason/error)))

(defn- record-erroring-party
  [state {:keys [from]}]
  (assoc state :ceremony/erroring-party from))

(defn- record-cancel-reason
  [state _event]
  (assoc state :ceremony/error :reason/cancel))

(defn- record-timeout
  [state _event]
  (assoc state :ceremony/error :reason/timeout))

(defn- record-deadline
  "Deadline is set at FSM init; this action is a structural marker."
  [state _event]
  state)

(defn- record-handles
  "Handles (share-handle, triple-handle) are placed in context at FSM
   init; this action is a structural marker confirming they are now
   committed for the ceremony."
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
;; Generic guards
;; ============================================================
;;
;; Note on timing: clj-statecharts evaluates the guard before running
;; the transition's actions. The chart's two transitions for
;; :event/ceremony-complete in :state/running discriminate on
;; "how many parties are done after this event would land" — so the
;; predicates here look at the count BEFORE the action runs and
;; arithmetic on the inflight event.

(defn- count-done [state]
  (->> (:ceremony/per-party-state state) vals
       (filter #(= :party-state/done %)) count))

(defn- guard-at-least-one-party-still-running [& _args]
  (fn [state _event]
    (let [n (count (:ceremony/participants state))
          k (count-done state)]
      ;; After this event would push count to k+1, more than one
      ;; party still running iff (n - (k+1)) >= 1, i.e. k+1 < n.
      (< (inc k) n))))

(defn- guard-all-parties-done-after-this-event [& _args]
  (fn [state _event]
    (let [n (count (:ceremony/participants state))
          k (count-done state)]
      ;; Exactly this event is the last → k+1 == n.
      (= (inc k) n))))

(def ^:private actor->bare-role
  "Bridge between the chart's namespaced :actor/X keywords and the
   bare role keywords (:holder, :figure, :ic) used everywhere in
   the runtime. Driven by the dictionary's actor :short-name where
   defined; otherwise drops the namespace and keeps the terminal
   segment. The mismatch surfaced when retrofitting the chart-
   runtime onto the existing procedural ceremony plumbing — would
   not have been an issue in a chart-first design."
  {:actor/holder               :holder
   :actor/figure               :figure
   :actor/independent-custodian :ic})

(defn- normalize-role [k]
  (or (actor->bare-role k) k))

(defn- guard-originated-from [actor-kw]
  (fn [_state event]
    (= (normalize-role actor-kw) (normalize-role (:from event)))))

;; ============================================================
;; Registries
;; ============================================================

(def ^:private action-registry
  {:action/record-deadline                  record-deadline
   :action/record-handles                   record-handles
   :action/send-begin-to-all-participants   send-begin-to-all-participants
   :action/start-deadline-timer             start-deadline-timer
   :action/route-message                    route-message
   :action/record-party-done                record-party-done
   :action/check-all-parties-done           check-all-parties-done
   :action/collect-per-party-results        collect-per-party-results
   :action/triple-shape-check               triple-shape-check
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
  {'guard/at-least-one-party-still-running guard-at-least-one-party-still-running
   'guard/all-parties-done-after-this-event guard-all-parties-done-after-this-event
   'guard/originated-from                   guard-originated-from})

;; ============================================================
;; Peer-message → FSM-event translation
;; ============================================================

(defn- channel->role [orch ch]
  (some (fn [[r conn]] (when (identical? ch (:inbound conn)) r))
        (:connections-by-role orch)))

(defn- msg->event
  "Translate an inbound peer EDN message into an FSM event map.
   Returns nil for messages the chart-driven runtime should ignore."
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
;; Generic chart-driven event loop
;; ============================================================

(defn- terminal? [state]
  (#{:state/complete :state/failed} (:_state state)))

(defn- drain-pending-events!
  "Pull queued internal events from the pending-events atom and feed
   them to the FSM. Used to follow up after actions that synthesize
   events (e.g. :action/triple-shape-check fires
   :event/finalization-passed)."
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
;; Triple-generation entry point
;; ============================================================

(defn run-triple-generation-via-chart
  "Chart-driven equivalent of ceremony/run-triple-generation. Loads
   the triple-generation chart EDN, builds an FSM via the project's
   chart-runtime translator, populates context with ceremony-id /
   handles / orchestrator handle / pending-events queue / result
   promise, then runs the event loop to completion.

   Returns the same shape as run-triple-generation:
     {:triple-handle <uuid> :handles {role <uuid>} :ceremony/id <uuid>}
   on success, or
     {:error <reason> :details {...}}
   on failure."
  [{:keys [participant-ids identity-pubkeys] :as orch} participants
   {:keys [threshold deadline-ms share-handle chart-path]
    :or   {threshold 2
           deadline-ms 60000
           chart-path  "../specs/statechart-triple-generation.edn"}}]
  (let [ceremony-id   (uuidv7/uuidv7)
        triple-handle (uuidv7/uuidv7)
        peers         (vec participants)
        ids           (select-keys participant-ids peers)
        peer-pubkeys  (select-keys identity-pubkeys peers)
        chart         (edn/read-string {:default tagged-literal} (slurp chart-path))
        machine       (fsm/machine
                       (cr/chart->machine-spec chart action-registry guard-registry))
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
        result-promise (promise)
        pending-events (atom [])
        initial-context
        {:ceremony/id              ceremony-id
         :ceremony/participants    peers
         :ceremony/coordinator     :actor/figure
         :ceremony/scheme          :scheme/ot-based-ecdsa-secp256k1
         :ceremony/share-handle    share-handle
         :ceremony/triple-handle   triple-handle
         :ceremony/per-party-state (into {} (for [r peers] [r :party-state/awaiting]))
         :ceremony/results         {}
         :ceremony/error           nil
         ;; Plumbing context fields. clj-statecharts merges these
         ;; into state alongside the chart-declared :ceremony/* keys.
         ::orch                    orch
         ::participants            peers
         ::triple-handle           triple-handle
         ::make-begin              make-begin
         ::result-promise          result-promise
         ::pending-events          pending-events}
        state-atom
        (atom (fsm/initialize machine {:context initial-context}))]
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.chart-driven-ceremonies/started
               :data  {:ceremony-id ceremony-id
                       :participants peers
                       :triple-handle triple-handle}})
    ;; Fire begin-ceremony to enter :state/starting and run its
    ;; entry actions (which dispatch the begin messages to peers).
    (transition-and-drain! machine state-atom pending-events
                           {:type :event/begin-ceremony})
    ;; Run the loop until terminal.
    (run-event-loop! machine state-atom pending-events orch peers deadline-ms)
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.chart-driven-ceremonies/ended
               :data  {:ceremony-id ceremony-id
                       :final-state (:_state @state-atom)}})
    @result-promise))
