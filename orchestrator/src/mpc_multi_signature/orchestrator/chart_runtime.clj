(ns mpc-multi-signature.orchestrator.chart-runtime
  "Bridge between this project's statechart EDN files (under specs/)
   and the clj-statecharts FSM engine.

   Stage 0.5 charts use a few project-specific conventions that don't
   match clj-statecharts directly:

     - State keys live under :statechart/states (not :states).
     - Parallel sub-regions live under :statechart/parallel-regions
       (not :regions, and the parent state lacks :type :parallel).
     - Actions are referred to by namespaced keywords like
       :action/route-message; a description string lives in
       :statechart/actions. The actual function is supplied by an
       action-registry the consumer passes in.
     - Guards are written as lists like (guard/originated-from
       :actor/holder); the head symbol identifies a higher-order
       function in a guard-registry that takes the trailing args
       and returns the actual predicate.
     - Eventless transitions are written :on {:auto :target} in
       some places (notably the per-party :party-state/relaying
       state). Translated to clj-statecharts's :always.
     - The chart files carry several documentation sections —
       :statechart/version, :statechart/dictionary,
       :statechart/scope, :statechart/cross-cutting,
       :statechart/properties, and the descriptive
       :statechart/actions / :statechart/guards maps. These are
       irrelevant at runtime and stripped here.

   The translator output is a value suitable for
   `(statecharts.core/machine ...)` to consume.")

;; ============================================================
;; Action and guard registry resolution
;; ============================================================

(defn- resolve-action
  "An action in a chart is a namespaced keyword like
   :action/route-message. The registry maps that keyword to a
   function (fn [state event] ...) which clj-statecharts will invoke
   on transition. Returns the resolved function or throws if missing."
  [action-registry action-kw]
  (or (get action-registry action-kw)
      (throw (ex-info "chart-runtime: unknown action keyword"
                      {:action action-kw
                       :registered (vec (keys action-registry))}))))

(defn- resolve-actions
  "Translate a vector of action keywords (or already-functions) to a
   vector of functions."
  [action-registry actions]
  (when actions
    (mapv (fn [a]
            (cond
              (fn? a)      a
              (keyword? a) (resolve-action action-registry a)
              :else        (throw (ex-info "chart-runtime: action must be a keyword or fn"
                                           {:action a}))))
          actions)))

(defn- resolve-guard
  "A guard in a chart is a list whose head is a symbol naming a
   guard-registry entry. The registry value is a higher-order function
   that takes the trailing args from the list and returns the actual
   predicate (fn [state event] ...). Lists with no trailing args
   resolve to a registry-supplied nullary predicate."
  [guard-registry guard-form]
  (cond
    (nil? guard-form)
    nil

    (fn? guard-form)
    guard-form

    (sequential? guard-form)
    (let [[head & args] guard-form
          maker (or (get guard-registry head)
                    (throw (ex-info "chart-runtime: unknown guard symbol"
                                    {:guard head
                                     :registered (vec (keys guard-registry))})))]
      (apply maker args))

    :else
    (throw (ex-info "chart-runtime: guard must be a list, fn, or nil"
                    {:guard guard-form}))))

(defn- resolve-guards
  "Charts express :guards [(guard/foo :arg)] as a vector of guard
   forms. clj-statecharts's :guard expects a single predicate. If
   multiple guard forms are present, AND them together."
  [guard-registry guards]
  (let [predicates (->> guards (map #(resolve-guard guard-registry %)) (remove nil?))]
    (case (count predicates)
      0 nil
      1 (first predicates)
      (fn [state event]
        (every? #(% state event) predicates)))))

;; ============================================================
;; Transition + state translation
;; ============================================================

(defn- translate-transition
  "Translate a single transition map: :target stays, :actions is
   resolved against the registry, :guards is collapsed into :guard."
  [action-registry guard-registry tx]
  (let [tx (if (:actions tx)
             (assoc tx :actions (resolve-actions action-registry (:actions tx)))
             tx)
        tx (if (:guards tx)
             (-> tx
                 (assoc :guard (resolve-guards guard-registry (:guards tx)))
                 (dissoc :guards))
             tx)]
    tx))

(defn- translate-on-entry
  "An :on map's value can be:
     - a keyword (target state name) — clj-statecharts accepts this
     - a single transition map
     - a vector of transition maps (guarded fallthrough)
   Translation preserves shape; only inner :actions/:guards are
   resolved."
  [action-registry guard-registry on-value]
  (cond
    (keyword? on-value) on-value
    (map?     on-value) (translate-transition action-registry guard-registry on-value)
    (vector?  on-value) (mapv #(translate-transition action-registry guard-registry %) on-value)
    :else
    (throw (ex-info "chart-runtime: unsupported :on value shape"
                    {:value on-value}))))

(declare translate-state)

(defn- translate-on-map
  "Translate a state's :on map (excluding :auto which is hoisted to
   the state-level :always by the caller, since clj-statecharts
   expects :always at state level, not nested inside :on)."
  [action-registry guard-registry on-map]
  (when on-map
    (reduce-kv
     (fn [acc event-kw on-val]
       (assoc acc event-kw (translate-on-entry action-registry guard-registry on-val)))
     {}
     on-map)))

(defn- translate-region
  "A region is itself a state map: it has :initial and :states. Just
   forward to translate-state."
  [action-registry guard-registry region]
  (translate-state action-registry guard-registry region))

(defn- translate-parallel-regions
  [action-registry guard-registry regions]
  (when regions
    (reduce-kv
     (fn [acc region-key region-spec]
       (assoc acc region-key (translate-region action-registry guard-registry region-spec)))
     {}
     regions)))

(defn- translate-states
  "Translate a :statechart/states map by recursively translating
   each child state."
  [action-registry guard-registry states]
  (when states
    (reduce-kv
     (fn [acc state-key state-spec]
       (assoc acc state-key (translate-state action-registry guard-registry state-spec)))
     {}
     states)))

(defn- translate-state
  "Translate a single state node. Recognized keys:
     :type           — preserved (e.g. :final)
     :initial        — preserved
     :entry / :exit  — action lists, resolved
     :on             — events map, resolved (with :auto hoisted out)
     :auto in :on    — hoisted to state-level :always (eventless
                       transition; clj-statecharts expects :always
                       at state level, not nested inside :on)
     :statechart/states OR :states — recursed as :states. The
       chart-level convention uses :statechart/states; per-region
       inner states use plain :states. We accept both.
     :statechart/parallel-regions — recursed as :regions, with
                                    :type :parallel set on this node"
  [action-registry guard-registry node]
  (let [;; Children may live under either key.
        children      (or (:statechart/states node) (:states node))
        regions       (:statechart/parallel-regions node)
        raw-on        (:on node)
        auto-entry    (:auto raw-on)
        on-without-auto (dissoc raw-on :auto)
        translated-on (when (seq on-without-auto)
                        (translate-on-map action-registry guard-registry
                                          on-without-auto))
        translated-always
        (when auto-entry
          (translate-on-entry action-registry guard-registry auto-entry))
        entries (:entry node)
        exits   (:exit node)]
    (cond-> (dissoc node :statechart/states :statechart/parallel-regions
                    :states :on :entry :exit)
      entries           (assoc :entry  (resolve-actions action-registry entries))
      exits             (assoc :exit   (resolve-actions action-registry exits))
      translated-on     (assoc :on     translated-on)
      translated-always (assoc :always translated-always)
      children          (assoc :states (translate-states action-registry guard-registry children))
      regions           (assoc :type :parallel
                               :regions (translate-parallel-regions
                                         action-registry guard-registry regions)))))

;; ============================================================
;; Top-level translation
;; ============================================================

(def ^:private documentation-keys
  "Top-level chart keys that exist for human readers and play no
   role at runtime; stripped before handing to clj-statecharts."
  #{:statechart/version :statechart/dictionary :statechart/scope
    :statechart/template
    :statechart/actions :statechart/guards
    :statechart/cross-cutting :statechart/properties})

(defn chart->machine-spec
  "Translate a project statechart EDN value into a clj-statecharts-
   shaped spec map. Resolves :action/X keywords against
   `action-registry` and (guard/X args...) lists against
   `guard-registry`. The result can be passed to
   `(statecharts.core/machine ...)`.

   Top-level chart keys recognized:
     :statechart/id      → :id
     :statechart/initial → :initial
     :statechart/context → :context
     :statechart/states  → :states (recursively translated)

   Top-level keys silently dropped: :statechart/version,
   :statechart/dictionary, :statechart/scope, :statechart/template,
   :statechart/actions (descriptions), :statechart/guards
   (descriptions), :statechart/cross-cutting, :statechart/properties.

   The :statechart/ceremony key is preserved (renamed :ceremony) so a
   downstream observer can identify which ceremony a machine value
   represents — clj-statecharts ignores unknown top-level keys."
  [chart action-registry guard-registry]
  (let [{:statechart/keys [id initial context states ceremony]} chart
        stripped (apply dissoc chart
                        (concat documentation-keys
                                [:statechart/id :statechart/initial
                                 :statechart/context :statechart/states
                                 :statechart/ceremony]))]
    (cond-> stripped
      id       (assoc :id id)
      initial  (assoc :initial initial)
      context  (assoc :context context)
      states   (assoc :states (translate-states action-registry guard-registry states))
      ceremony (assoc :ceremony ceremony))))
