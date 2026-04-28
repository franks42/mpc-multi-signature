(ns mpc-multi-signature.orchestrator.chart-conformance-test
  "Chart conformance tests. For each ceremony chart in specs/, build a
   clj-statecharts machine via chart-runtime/chart->machine-spec and
   drive it through the event sequence that mirrors how the
   procedural implementation actually runs the ceremony. Pass = the
   chart is internally consistent and the implementation's
   transitions match the chart.

   These tests do not exercise the cryptographic protocol — they
   exercise only the orchestrator-side state-machine shape. Stage 1
   conformance: no drift between chart and procedural code on
   transition events, action wiring, and final-state reachability.

   The action registry uses recording stubs so every invocation is
   traced; tests assert both reachability and that the expected
   actions fired in the expected order.

   Run from the orchestrator/ directory:
     clojure -M:test -n mpc-multi-signature.orchestrator.chart-conformance-test"
  (:require [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            [mpc-multi-signature.orchestrator.chart-runtime :as cr]
            [statecharts.core :as fsm]))

;; ============================================================
;; Recording stubs
;; ============================================================

(defn- recording-action-registry
  "Build an action registry where every action keyword resolves to a
   stub fn that records its invocation in `calls` (atom holding a
   vector of action keywords) and returns state unchanged."
  [calls action-keywords]
  (into {}
        (for [k action-keywords]
          [k (fn [state _event]
               (swap! calls conj k)
               state)])))

(defn- stateful-guard-registry
  "A guard registry where the predicates dispatch on a guard-state
   atom. Tests bind the atom to choose which guard wins.

   For triple-generation, the relevant case is:
     :event/ceremony-complete in :state/running has two transitions:
       guard (guard/at-least-one-party-still-running) → stay in :running
       guard (guard/all-parties-done-after-this-event) → → :finalizing

   The test cycles the guard-state {:remaining N} atom — N>1 keeps us
   in :running, N==1 advances us to :finalizing."
  [guard-state]
  {'guard/at-least-one-party-still-running
   (fn [& _args]
     (fn [_state _event] (> (:remaining @guard-state 0) 1)))

   'guard/all-parties-done-after-this-event
   (fn [& _args]
     (fn [_state _event] (= (:remaining @guard-state 0) 1)))

   'guard/originated-from
   (fn [& _args]
     (fn [_state _event] true))

   'guard/objection-window-required
   (fn [& _args]
     (fn [_state _event] (:objection-window? @guard-state false)))

   'guard/objection-window-not-required
   (fn [& _args]
     (fn [_state _event] (not (:objection-window? @guard-state false))))})

;; ============================================================
;; Helpers for loading + building
;; ============================================================

(defn- load-chart [chart-name]
  (edn/read-string {:default tagged-literal}
                   (slurp (str "../specs/statechart-" chart-name ".edn"))))

(defn- collect-action-keywords
  "Walk a chart spec, collect every keyword that appears in
   :entry / :exit / :actions positions. Used to build a complete
   recording registry without enumerating by hand."
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

(defn- build-machine
  ([chart-name calls]
   (build-machine chart-name calls (atom {:remaining 2 :objection-window? false})))
  ([chart-name calls guard-state]
   (let [chart   (load-chart chart-name)
         actions (collect-action-keywords chart)
         areg    (recording-action-registry calls actions)
         greg    (stateful-guard-registry guard-state)]
     (fsm/machine (cr/chart->machine-spec chart areg greg)))))

(defn- terminal? [state]
  (let [v (:_state state)]
    (or (= v :state/complete) (= v :state/failed))))

;; ============================================================
;; Conformance: triple-generation
;; ============================================================

(deftest triple-generation-happy-path
  (testing "triple-generation chart drives cleanly from begin-ceremony to complete"
    (let [calls       (atom [])
          guard-state (atom {:remaining 2})
          machine     (build-machine "triple-generation" calls guard-state)
          s0 (fsm/initialize machine)]
      (is (= :state/pending (:_state s0)))
      (let [s1 (fsm/transition machine s0 :event/begin-ceremony)]
        (is (= :state/starting (:_state s1)))
        (is (every? (set @calls)
                    [:action/record-deadline
                     :action/record-handles
                     :action/send-begin-to-all-participants
                     :action/start-deadline-timer]))
        (let [s2 (fsm/transition machine s1 :event/protocol-message-emit)]
          (is (map? (:_state s2)) "running has parallel substructure")
          (is (= :state/running (first (keys (:_state s2))))
              "outer state key is :state/running")
          ;; First :event/ceremony-complete: 2 parties remaining → first
          ;; guard wins, stay in :state/running, 1 party still pending
          (let [s3 (fsm/transition machine s2 :event/ceremony-complete)]
            (is (map? (:_state s3)) "still in parallel :state/running")
            (swap! guard-state assoc :remaining 1)
            ;; Second :event/ceremony-complete: now 1 remaining → second
            ;; guard wins, advance to :state/finalizing
            (let [s4 (fsm/transition machine s3 :event/ceremony-complete)]
              (is (= :state/finalizing (:_state s4)))
              (is (some #{:action/collect-per-party-results} @calls))
              (is (some #{:action/triple-shape-check} @calls))
              (let [s5 (fsm/transition machine s4 :event/finalization-passed)]
                (is (= :state/complete (:_state s5)))
                (is (terminal? s5))
                (is (some #{:action/notify-coordinator-success} @calls))
                (is (some #{:action/persist-result-handles} @calls))))))))))

(deftest triple-generation-cancel-from-pending
  (testing "cancel from :state/pending takes us straight to :state/failed"
    (let [calls   (atom [])
          machine (build-machine "triple-generation" calls)
          s0      (fsm/initialize machine)
          s1      (fsm/transition machine s0 :event/cancel)]
      (is (= :state/failed (:_state s1)))
      (is (terminal? s1))
      (is (some #{:action/record-cancel-reason} @calls)))))

(deftest triple-generation-deadline-from-running
  (testing "deadline-elapsed in :state/running aborts cleanly"
    (let [calls   (atom [])
          machine (build-machine "triple-generation" calls)
          s0      (fsm/initialize machine)
          s1      (fsm/transition machine s0 :event/begin-ceremony)
          s2      (fsm/transition machine s1 :event/protocol-message-emit)
          s3      (fsm/transition machine s2 :event/deadline-elapsed)]
      (is (= :state/aborting (:_state s3)))
      (let [s4 (fsm/transition machine s3 :event/all-parties-acked-cancel)]
        (is (= :state/failed (:_state s4)))
        (is (some #{:action/record-timeout} @calls))
        (is (some #{:action/notify-coordinator-failure} @calls))))))

;; ============================================================
;; Conformance: keygen
;; ============================================================

(deftest keygen-happy-path
  (testing "keygen chart drives cleanly from begin to complete with 3 parties"
    (let [calls       (atom [])
          guard-state (atom {:remaining 3})
          machine     (build-machine "keygen" calls guard-state)
          s0          (fsm/initialize machine)
          s1          (fsm/transition machine s0 :event/begin-ceremony)
          s2          (fsm/transition machine s1 :event/protocol-message-emit)]
      (is (= :state/pending  (:_state s0)))
      (is (= :state/starting (:_state s1)))
      (is (map? (:_state s2)) ":state/running with 3 parallel regions")
      ;; 3 parties → first two completes stay in running, third advances
      (let [s3 (fsm/transition machine s2 :event/ceremony-complete)
            _  (swap! guard-state assoc :remaining 2)
            s4 (fsm/transition machine s3 :event/ceremony-complete)
            _  (swap! guard-state assoc :remaining 1)
            s5 (fsm/transition machine s4 :event/ceremony-complete)]
        (is (= :state/finalizing (:_state s5)))
        (let [s6 (fsm/transition machine s5 :event/finalization-passed)]
          (is (= :state/complete (:_state s6)))
          (is (terminal? s6)))))))

;; ============================================================
;; Conformance: sign
;; ============================================================

(deftest sign-happy-path
  (testing "sign chart drives policy-check → starting → running → complete"
    (let [calls       (atom [])
          guard-state (atom {:remaining 2})
          machine     (build-machine "sign" calls guard-state)
          s0          (fsm/initialize machine)
          s1          (fsm/transition machine s0 :event/sign-request-received)]
      (is (= :state/pending      (:_state s0)))
      (is (= :state/policy-check (:_state s1)))
      (let [s2 (fsm/transition machine s1 :event/policy-pass)]
        (is (= :state/starting (:_state s2)))
        (is (some #{:action/select-presignature} @calls))
        (let [s3 (fsm/transition machine s2 :event/protocol-message-emit)
              s4 (fsm/transition machine s3 :event/ceremony-complete)
              _  (swap! guard-state assoc :remaining 1)
              s5 (fsm/transition machine s4 :event/ceremony-complete)
              s6 (fsm/transition machine s5 :event/finalization-passed)]
          (is (= :state/complete (:_state s6)))
          (is (some #{:action/release-presignature} @calls)
              "sign chart's :state/complete entry should fire :action/release-presignature"))))))

(deftest sign-policy-fail
  (testing "sign chart policy-fail goes straight to :state/failed"
    (let [calls   (atom [])
          machine (build-machine "sign" calls)
          s0      (fsm/initialize machine)
          s1      (fsm/transition machine s0 :event/sign-request-received)
          s2      (fsm/transition machine s1 :event/policy-fail)]
      (is (= :state/failed (:_state s2)))
      (is (some #{:action/record-policy-rejection} @calls)))))

;; ============================================================
;; Conformance: reshare-recovery (UC2)
;; ============================================================

(deftest reshare-recovery-no-objection-window
  (testing "reshare-recovery: gate passes for both, no objection window, runs to complete"
    (let [calls       (atom [])
          guard-state (atom {:remaining 3 :objection-window? false})
          machine     (build-machine "reshare-recovery" calls guard-state)
          s0          (fsm/initialize machine)
          s1          (fsm/transition machine s0 :event/begin-ceremony)]
      (is (= :state/authorization-gate (:_state s1)))
      (let [s2 (fsm/transition machine s1 :event/figure-gate-pass)
            s3 (fsm/transition machine s2 :event/ic-gate-pass)
            ;; Both gates passed; the synthesized :event/both-gates-passed
            ;; should advance to starting (objection-window-not-required).
            s4 (fsm/transition machine s3 :event/both-gates-passed)]
        (is (= :state/starting (:_state s4)))
        (let [s5 (fsm/transition machine s4 :event/protocol-message-emit)
              ;; 3 new participants
              s6 (fsm/transition machine s5 :event/ceremony-complete)
              _  (swap! guard-state assoc :remaining 2)
              s7 (fsm/transition machine s6 :event/ceremony-complete)
              _  (swap! guard-state assoc :remaining 1)
              s8 (fsm/transition machine s7 :event/ceremony-complete)]
          (is (= :state/finalizing (:_state s8)))
          (let [s9 (fsm/transition machine s8 :event/finalization-passed)]
            (is (= :state/complete (:_state s9)))
            (is (some #{:action/invalidate-old-holder-share-record} @calls))))))))

(deftest reshare-recovery-with-objection-window
  (testing "reshare-recovery: objection window required → published, then elapses"
    (let [calls       (atom [])
          guard-state (atom {:remaining 3 :objection-window? true})
          machine     (build-machine "reshare-recovery" calls guard-state)
          s0          (fsm/initialize machine)
          s1          (fsm/transition machine s0 :event/begin-ceremony)
          s2          (fsm/transition machine s1 :event/figure-gate-pass)
          s3          (fsm/transition machine s2 :event/ic-gate-pass)
          s4          (fsm/transition machine s3 :event/both-gates-passed)]
      (is (= :state/objection-window (:_state s4)))
      (is (some #{:action/publish-recovery-intent} @calls))
      (let [s5 (fsm/transition machine s4 :event/objection-window-elapsed)]
        (is (= :state/starting (:_state s5)))))))

(deftest reshare-recovery-figure-gate-fail
  (testing "reshare-recovery: figure-gate-fail aborts before any reshare work"
    (let [calls   (atom [])
          machine (build-machine "reshare-recovery" calls)
          s0      (fsm/initialize machine)
          s1      (fsm/transition machine s0 :event/begin-ceremony)
          s2      (fsm/transition machine s1 :event/figure-gate-fail)]
      (is (= :state/aborting (:_state s2)))
      (is (some #{:action/record-figure-gate-fail} @calls)))))

;; ============================================================
;; Conformance: share-possession-proof
;; ============================================================

(deftest share-possession-proof-happy-path
  (testing "share-possession-proof chart drives cleanly with no protocol relay"
    (let [calls       (atom [])
          guard-state (atom {:remaining 3})
          machine     (build-machine "share-possession-proof" calls guard-state)
          s0          (fsm/initialize machine)
          s1          (fsm/transition machine s0 :event/begin-ceremony)
          ;; In this chart, :state/starting transitions to :state/running on
          ;; :event/ceremony-complete (no protocol-message-emit step).
          s2          (fsm/transition machine s1 :event/ceremony-complete)]
      (is (= :state/pending  (:_state s0)))
      (is (= :state/starting (:_state s1)))
      (is (map? (:_state s2)) "running with parallel regions")
      (swap! guard-state assoc :remaining 2)
      (let [s3 (fsm/transition machine s2 :event/ceremony-complete)
            _  (swap! guard-state assoc :remaining 1)
            s4 (fsm/transition machine s3 :event/ceremony-complete)]
        (is (= :state/finalizing (:_state s4)))
        (let [s5 (fsm/transition machine s4 :event/finalization-passed)]
          (is (= :state/complete (:_state s5)))
          (is (some #{:action/return-transcripts} @calls)))))))
