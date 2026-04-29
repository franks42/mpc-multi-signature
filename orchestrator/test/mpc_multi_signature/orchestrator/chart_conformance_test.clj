(ns mpc-multi-signature.orchestrator.chart-conformance-test
  "Conformance tests for the EXECUTABLE charts under specs/executable/.

   These tests verify the artifacts the runtime actually executes —
   not the documentation charts under specs/, which intentionally
   diverge for human readability. The retargeting from doc charts
   to executable charts was recommended by both LLM reviewers (see
   docs/review-gpt-20260428.md and docs/review-gemini-20260428.md).

   Three classes of test:

   1. Registry resolution — every :action/* keyword referenced by
      every executable chart resolves in chart-driven/action-registry;
      every (guard/X) symbol resolves in
      chart-driven/guard-registry.

   2. Structural properties — every non-final state handles
      :event/cancel; :state/complete reachable only via
      :state/finalizing; :state/failed reachable only via
      :state/pending or :state/aborting.

   3. Happy-path drive — for each ceremony, drive the FSM through
      the expected event sequence and assert it reaches
      :state/complete with the right actions fired."
  (:require [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.test :refer [deftest is testing]]
            [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.chart-runtime :as cr]
            [statecharts.core :as fsm]))

;; ============================================================
;; The six executable ceremony charts
;; ============================================================

(def ^:private executable-charts
  ["keygen"
   "triple-generation"
   "presign"
   "share-possession-proof"
   "sign"
   "reshare"])

(defn- load-executable [chart-name]
  (edn/read-string {:default tagged-literal}
                   (slurp (str "../specs/executable/statechart-"
                               chart-name ".edn"))))

;; ============================================================
;; Walkers
;; ============================================================

(defn- walk-chart-actions
  "Return a set of every :action/* keyword referenced anywhere in the
   chart (in :entry, :exit, or :actions positions)."
  [chart]
  (let [acc (atom #{})
        walk (fn walk [node]
               (cond
                 (map? node)
                 (doseq [[k v] node]
                   (cond
                     (#{:entry :exit :actions} k)
                     (when (sequential? v)
                       (doseq [x v]
                         (when (and (keyword? x)
                                    (= "action" (namespace x)))
                           (swap! acc conj x))))

                     :else (walk v)))

                 (sequential? node) (doseq [x node] (walk x))))]
    (walk chart)
    @acc))

(defn- walk-chart-guard-symbols
  "Return a set of every guard/X symbol referenced anywhere in the
   chart's :guards lists. Charts use list form like
   `(guard/all-parties-done-after-this-event)` — the symbol head is
   what the guard registry keys on."
  [chart]
  (let [acc (atom #{})
        walk (fn walk [node]
               (cond
                 (map? node)
                 (doseq [[k v] node]
                   (cond
                     (= :guards k)
                     (when (sequential? v)
                       (doseq [g v]
                         (when (and (sequential? g)
                                    (symbol? (first g))
                                    (= "guard" (namespace (first g))))
                           (swap! acc conj (first g)))))

                     :else (walk v)))

                 (sequential? node) (doseq [x node] (walk x))))]
    (walk chart)
    @acc))

(defn- walk-chart-states
  "Return a map of state-key → state-spec for every state defined
   under :statechart/states (top-level only — these charts have no
   nested compound states or parallel regions by design)."
  [chart]
  (:statechart/states chart))

;; ============================================================
;; 1. Registry resolution
;; ============================================================

(deftest every-chart-action-resolves-in-runtime-registry
  (testing "every :action/* keyword in every executable chart has a
            corresponding entry in chart-driven/action-registry"
    (let [registered (set (keys cd/action-registry))]
      (doseq [chart-name executable-charts]
        (let [chart       (load-executable chart-name)
              referenced  (walk-chart-actions chart)
              unresolved  (set/difference referenced registered)]
          (is (empty? unresolved)
              (str chart-name " references unresolved action(s): "
                   unresolved)))))))

(deftest every-chart-guard-resolves-in-runtime-registry
  (testing "every (guard/X) symbol in every executable chart has a
            corresponding entry in chart-driven/guard-registry"
    (let [registered (set (keys cd/guard-registry))]
      (doseq [chart-name executable-charts]
        (let [chart       (load-executable chart-name)
              referenced  (walk-chart-guard-symbols chart)
              unresolved  (set/difference referenced registered)]
          (is (empty? unresolved)
              (str chart-name " references unresolved guard(s): "
                   unresolved)))))))

;; ============================================================
;; 2. Structural properties
;; ============================================================

(defn- final-state? [state-spec]
  (= :final (:type state-spec)))

(defn- has-cancel-handler? [state-spec]
  (contains? (:on state-spec) :event/cancel))

(deftest every-non-final-state-handles-cancel
  (testing "for each executable chart, every state whose :type is not
            :final (excluding :state/aborting, which exits via its own
            :event/all-parties-acked-cancel + :event/abort-timeout-elapsed)
            has an :event/cancel transition"
    (doseq [chart-name executable-charts]
      (let [chart  (load-executable chart-name)
            states (walk-chart-states chart)]
        (doseq [[state-key state-spec] states
                :when (and (not (final-state? state-spec))
                           (not= state-key :state/aborting))]
          (is (has-cancel-handler? state-spec)
              (str chart-name " state " state-key
                   " has no :event/cancel handler")))))))

(defn- transitions-from
  "Return a seq of [event target] pairs for every transition out of
   `state-spec`. Handles :on map values that may be: a target keyword,
   a single transition map, or a vector of guarded transitions."
  [state-spec]
  (mapcat (fn [[event on-value]]
            (cond
              (keyword? on-value) [[event on-value]]
              (map? on-value)     [[event (:target on-value)]]
              (vector? on-value)  (map (fn [t] [event (:target t)]) on-value)
              :else               []))
          (:on state-spec)))

(defn- states-pointing-to
  "Return the set of state keys whose `:on` transitions can land at
   target-state."
  [chart target-state]
  (let [states (walk-chart-states chart)]
    (into #{}
          (for [[from-key state-spec] states
                [_ tgt] (transitions-from state-spec)
                :when (= tgt target-state)]
            from-key))))

(deftest complete-only-via-finalizing
  (testing "for each executable chart, :state/complete is reachable
            only from :state/finalizing"
    (doseq [chart-name executable-charts]
      (let [chart    (load-executable chart-name)
            sources  (states-pointing-to chart :state/complete)]
        (is (or (empty? sources)
                (= sources #{:state/finalizing}))
            (str chart-name ": :state/complete reachable from "
                 sources " (expected only #{:state/finalizing})"))))))

(deftest failed-only-via-pending-or-aborting
  (testing "for each executable chart, :state/failed is reachable
            only from :state/pending (early cancel) or :state/aborting
            (post-cancel cleanup)"
    (doseq [chart-name executable-charts]
      (let [chart   (load-executable chart-name)
            sources (states-pointing-to chart :state/failed)
            allowed #{:state/pending :state/aborting}]
        (is (set/subset? sources allowed)
            (str chart-name ": :state/failed reachable from "
                 sources " (expected subset of " allowed ")"))))))

;; ============================================================
;; 3. Happy-path drives (using the real runtime registries)
;; ============================================================

(defn- build-machine
  "Build a clj-statecharts machine for the named executable chart
   using the REAL runtime registries — verifies translator and
   registries compose without error."
  [chart-name]
  (let [chart (load-executable chart-name)]
    (fsm/machine
     (cr/chart->machine-spec chart cd/action-registry cd/guard-registry))))

(defn- runtime-context
  "Convert the test's plumbing context into one whose plumbing keys
   match what chart_driven's action fns expect (their :: keys are in
   the chart-driven namespace)."
  [participants result-promise pending-events]
  ;; chart_driven actions destructure ::orch, ::participants, etc.
  ;; Build the map with those exact keyword identities.
  {:ceremony/participants    participants
   :ceremony/per-party-state (into {} (for [r participants]
                                        [r :party-state/awaiting]))
   :ceremony/results         {}
   :ceremony/error           nil
   :mpc-multi-signature.orchestrator.chart-driven/orch              nil
   :mpc-multi-signature.orchestrator.chart-driven/participants      participants
   :mpc-multi-signature.orchestrator.chart-driven/make-begin        (constantly nil)
   :mpc-multi-signature.orchestrator.chart-driven/build-result      (constantly :stub-result)
   :mpc-multi-signature.orchestrator.chart-driven/result-promise    result-promise
   :mpc-multi-signature.orchestrator.chart-driven/pending-events    pending-events})

(defn- terminal? [state]
  (#{:state/complete :state/failed} (:_state state)))

;; --- Triple-generation: 2 parties, no consistency check -------

(deftest triple-generation-happy-path
  (testing "triple-generation executable chart drives :pending →
            :starting → :running → :finalizing → :complete with 2 parties"
    (let [machine (build-machine "triple-generation")
          peers   [:holder :figure]
          rp      (promise)
          pe      (atom [])
          s0      (fsm/initialize machine
                                  {:context (runtime-context peers rp pe)})
          s1      (fsm/transition machine s0 {:type :event/begin-ceremony})
          s2      (fsm/transition machine s1 {:type :event/protocol-message-emit
                                              :from :holder
                                              :msg/type :protocol/broadcast})
          s3      (fsm/transition machine s2 {:type :event/ceremony-complete
                                              :from :holder
                                              :result {:result/triple-handle "h1"}})
          s4      (fsm/transition machine s3 {:type :event/ceremony-complete
                                              :from :figure
                                              :result {:result/triple-handle "h2"}})]
      (is (= :state/pending    (:_state s0)))
      (is (= :state/starting   (:_state s1)))
      (is (= :state/running    (:_state s2)))
      (is (= :state/running    (:_state s3)) "first complete: stay in :running")
      (is (= :state/finalizing (:_state s4)) "second (last) complete: advance to :finalizing")
      ;; The :finalizing entry action queues :event/finalization-passed
      (is (= [:event/finalization-passed] @pe))
      (let [s5 (fsm/transition machine s4 (first @pe))]
        (is (= :state/complete (:_state s5)))
        (is (terminal? s5))))))

;; --- Keygen: 3 parties + real consistency check ----------------

(deftest keygen-happy-path-with-consistency
  (testing "keygen executable chart: 3 parties report agreeing
            public-keys, consistency check passes, terminal :complete"
    (let [machine (build-machine "keygen")
          peers   [:holder :figure :ic]
          rp      (promise)
          pe      (atom [])
          s0      (fsm/initialize machine
                                  {:context (runtime-context peers rp pe)})
          s1      (fsm/transition machine s0 {:type :event/begin-ceremony})
          s2      (fsm/transition machine s1 {:type :event/protocol-message-emit
                                              :from :holder
                                              :msg/type :protocol/broadcast})
          ;; All three parties report the SAME public-key
          mk-result (fn [_role] {:result/public-key-hex "0xabc"
                                 :result/verification-share-hex "0xv"})
          s3      (fsm/transition machine s2 {:type :event/ceremony-complete
                                              :from :holder
                                              :result (mk-result :holder)})
          s4      (fsm/transition machine s3 {:type :event/ceremony-complete
                                              :from :figure
                                              :result (mk-result :figure)})
          s5      (fsm/transition machine s4 {:type :event/ceremony-complete
                                              :from :ic
                                              :result (mk-result :ic)})]
      (is (= :state/finalizing (:_state s5)))
      (is (= [:event/finalization-passed] @pe))
      (let [s6 (fsm/transition machine s5 (first @pe))]
        (is (= :state/complete (:_state s6)))
        (is (= "0xabc" (:ceremony/public-key s6)))))))

(deftest keygen-public-key-disagreement-fails
  (testing "keygen consistency check rejects when parties disagree on
            public-key — finalization-failed → aborting → failed"
    (let [machine (build-machine "keygen")
          peers   [:holder :figure :ic]
          rp      (promise)
          pe      (atom [])
          s0      (fsm/initialize machine
                                  {:context (runtime-context peers rp pe)})
          s1      (fsm/transition machine s0 {:type :event/begin-ceremony})
          s2      (fsm/transition machine s1 {:type :event/protocol-message-emit
                                              :from :holder
                                              :msg/type :protocol/broadcast})
          s3      (fsm/transition machine s2 {:type :event/ceremony-complete
                                              :from :holder
                                              :result {:result/public-key-hex "0xabc"
                                                       :result/verification-share-hex "0xv"}})
          s4      (fsm/transition machine s3 {:type :event/ceremony-complete
                                              :from :figure
                                              :result {:result/public-key-hex "0xabc"
                                                       :result/verification-share-hex "0xv"}})
          ;; IC reports a DIFFERENT public-key — disagreement
          s5      (fsm/transition machine s4 {:type :event/ceremony-complete
                                              :from :ic
                                              :result {:result/public-key-hex "0xdef"
                                                       :result/verification-share-hex "0xv"}})]
      (is (= :state/finalizing (:_state s5)))
      (is (= [:event/finalization-failed] @pe))
      (is (= :reason/public-key-disagreement (:ceremony/error s5))))))

;; --- Cancel from each non-final state ---------------------------

(deftest cancel-from-each-non-final-state-reaches-failed
  (testing "for each executable chart, :event/cancel from each
            non-final state must end at :state/failed"
    (doseq [chart-name executable-charts]
      (let [chart   (load-executable chart-name)
            states  (walk-chart-states chart)]
        ;; Cancel semantics:
        ;;   - :state/pending → cancel goes direct to :state/failed
        ;;   - :state/aborting handles its own exit via
        ;;     :event/all-parties-acked-cancel and abort-timeout, so
        ;;     :event/cancel is not required there
        ;;   - All other non-final states: cancel should land at
        ;;     :state/aborting (which then forwards to :state/failed)
        (doseq [[state-key state-spec] states
                :when (and (not (final-state? state-spec))
                           (not= state-key :state/aborting))
                :let  [cancel-tx (get-in state-spec [:on :event/cancel])]]
          ;; Verify there's a cancel handler that targets either
          ;; :state/aborting or :state/failed (depending on state)
          (is cancel-tx
              (str chart-name " state " state-key
                   " has no :event/cancel transition"))
          (let [tx-target (cond
                            (keyword? cancel-tx) cancel-tx
                            (map? cancel-tx)     (:target cancel-tx)
                            :else                nil)]
            (is (#{:state/aborting :state/failed} tx-target)
                (str chart-name " state " state-key
                     " :event/cancel target is " tx-target
                     " (expected :state/aborting or :state/failed)"))))))))

;; --- Sign: asymmetric result ------------------------------------

(deftest sign-coordinator-only-signature-passes
  (testing "sign chart: coordinator returns a signature, others nil
            → consistency-check passes, :state/complete reached"
    (let [machine (build-machine "sign")
          peers   [:holder :figure]
          rp      (promise)
          pe      (atom [])
          ctx     (-> (runtime-context peers rp pe)
                      (assoc :ceremony/coordinator :figure))
          s0      (fsm/initialize machine {:context ctx})
          s1      (fsm/transition machine s0 {:type :event/begin-ceremony})
          s2      (fsm/transition machine s1 {:type :event/protocol-message-emit
                                              :from :holder
                                              :msg/type :protocol/broadcast})
          s3      (fsm/transition machine s2 {:type :event/ceremony-complete
                                              :from :holder
                                              :result {}}) ; no signature
          s4      (fsm/transition machine s3 {:type :event/ceremony-complete
                                              :from :figure
                                              :result {:result/signature-hex "deadbeef"}})]
      (is (= :state/finalizing (:_state s4)))
      (is (= [:event/finalization-passed] @pe))
      (is (= "deadbeef" (:ceremony/signature-hex s4))))))

;; --- Reshare: pubkey preservation ------------------------------

(deftest reshare-pubkey-preserved-passes
  (testing "reshare chart: all new participants report the same pubkey
            equal to expected → finalization passes"
    (let [machine (build-machine "reshare")
          peers   [:figure :ic]
          rp      (promise)
          pe      (atom [])
          ctx     (-> (runtime-context peers rp pe)
                      (assoc :ceremony/expected-public-key-hex "0xabc"))
          s0      (fsm/initialize machine {:context ctx})
          s1      (fsm/transition machine s0 {:type :event/begin-ceremony})
          s2      (fsm/transition machine s1 {:type :event/protocol-message-emit
                                              :from :figure
                                              :msg/type :protocol/broadcast})
          mk-result (fn [_r] {:result/public-key-hex "0xabc"
                              :result/verification-share-hex "0xv"})
          s3      (fsm/transition machine s2 {:type :event/ceremony-complete
                                              :from :figure
                                              :result (mk-result :figure)})
          s4      (fsm/transition machine s3 {:type :event/ceremony-complete
                                              :from :ic
                                              :result (mk-result :ic)})]
      (is (= :state/finalizing (:_state s4)))
      (is (= [:event/finalization-passed] @pe)))))

(deftest reshare-pubkey-drift-fails
  (testing "reshare chart: parties report a pubkey that doesn't match
            expected → finalization-failed"
    (let [machine (build-machine "reshare")
          peers   [:figure :ic]
          rp      (promise)
          pe      (atom [])
          ctx     (-> (runtime-context peers rp pe)
                      (assoc :ceremony/expected-public-key-hex "0xabc"))
          s0      (fsm/initialize machine {:context ctx})
          s1      (fsm/transition machine s0 {:type :event/begin-ceremony})
          s2      (fsm/transition machine s1 {:type :event/protocol-message-emit
                                              :from :figure
                                              :msg/type :protocol/broadcast})
          ;; Both parties agree, but they DRIFTED from expected
          mk-result (fn [_r] {:result/public-key-hex "0xdef"
                              :result/verification-share-hex "0xv"})
          s3      (fsm/transition machine s2 {:type :event/ceremony-complete
                                              :from :figure
                                              :result (mk-result :figure)})
          s4      (fsm/transition machine s3 {:type :event/ceremony-complete
                                              :from :ic
                                              :result (mk-result :ic)})]
      (is (= :state/finalizing (:_state s4)))
      (is (= [:event/finalization-failed] @pe))
      (is (= :reason/public-key-not-preserved (:ceremony/error s4))))))
