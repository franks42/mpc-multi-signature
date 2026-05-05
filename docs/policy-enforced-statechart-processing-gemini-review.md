# Review: Policy-Enforced Statechart Processing

## 1. High-Level Assessment
The insights presented in `docs/policy-enforced-statechart-processing.md` represent a mature and highly pragmatic approach to integrating policy into distributed state machines. Recognizing that *omitting* a policy engine still implies a policy (usually "allow all") is a critical realization. 

By modeling Policy Enforcement Points (PEPs) as explicit flow states (`:state/begin-authorization`) rather than burying them in transition guards or orthogonal middleware, you achieve several major architectural wins:
* **Visibility:** The ceremony's shape honestly reflects the real-world operational pauses (waiting for an authorization decision).
* **Auditability:** Policy evaluations naturally emit statechart transitions. The chore of "logging decisions" is solved for free by the orchestrator's existing state transition logs.
* **Separation of Concerns:** The FSM handles the *lifecycle routing* (PEP), while a completely pure, stateless function handles the *logic* (PDP: Policy Decision Point).

## 2. Specific Observations & Recommendations

### The "Trivial PDP" Bootstrapping
The suggestion to introduce a Trivial PDP (a simple function returning `:permit-all` or `:deny-all`) is excellent. 
**Recommendation:** Implement the mode flag via the process context or REPL injection initially. This allows you to immediately write unit tests that verify the `:deny-all` rejection paths, securing the FSM routing logic long before you parse your first Datalog policy rule. 

### Addressing Wait States (Async Policy)
The document correctly notes that PDP evaluations might become async (e.g., waiting for an external TAS).
**Recommendation:** Ensure your `clj-statecharts` execution model handles the `:action/dispatch-begin-policy-evaluation` asynchronously without blocking the orchestrator. The action should fire a side-effect that eventually places an `:event/begin-authorized` or `:event/begin-rejected` onto the FSM's event queue.

### The Missing "Check" on Sign
In `specs/executable/statechart-sign.edn`, there is currently a known gap where the issuer-policy gate is described in documentation but not enforced in the executable chart. We can apply the document's precise advice to bridge this gap now.

## 3. Concrete Example: Integrating Policy into `statechart-sign.edn`

Below is the modified executable statechart for the Sign ceremony. It demonstrates exactly how to wedge the `:state/begin-authorization` between `pending` and `starting`, acting as the explicit PEP for the issuer-policy evaluation.

```clojure
;; Modified snippet of specs/executable/statechart-sign.edn

{:statechart/id           :statechart/ceremony-sign-exec
 :statechart/version      "0.3.0" ;; Bumped version for policy integration
 :statechart/ceremony     :ceremony/sign
 :statechart/dictionary   "../data-dictionary.edn"
 :statechart/scope        "Orchestrator-side per-ceremony lifecycle, executable"

 :statechart/context
 {:ceremony/id              nil
  :ceremony/participants    nil
  :ceremony/coordinator     nil
  :ceremony/share-handle    nil
  :ceremony/presig-handle   nil
  :ceremony/digest-hex      nil
  :ceremony/signature-hex   nil
  :ceremony/per-party-state {}
  :ceremony/results         {}
  :ceremony/error           nil
  :policy/rejection-reason  nil} ;; NEW: Track why a policy failed

 :statechart/initial :state/pending

 :statechart/states
 {:state/pending
  {:on {:event/begin-ceremony
        ;; REDIRECTED: Pending no longer goes straight to starting.
        ;; It enters the authorization gate.
        {:target  :state/begin-authorization
         :actions [:action/record-handles]}

        :event/cancel
        {:target  :state/failed
         :actions [:action/record-cancel-reason]}}}

  ;; NEW: The Policy Enforcement Point (PEP)
  :state/begin-authorization
  {:entry [:action/dispatch-begin-policy-evaluation]
   :on   {:event/begin-authorized
          {:target :state/starting}

          :event/begin-rejected
          {:target  :state/failed
           :actions [:action/record-policy-rejection]}

          :event/cancel
          {:target  :state/failed
           :actions [:action/record-cancel-reason]}}}

  :state/starting
  {:entry [:action/send-begin-to-all-participants
           :action/start-deadline-timer]
   :on   {:event/protocol-message-emit
          {:target  :state/running
           :actions [:action/route-message]}

          ;; ... (unchanged error/cancel/deadline handlers) ...
          }}

  ;; ... :state/running, :state/finalizing, :state/aborting remain identical ...

  :state/failed
  {:type  :final
   :entry [:action/notify-coordinator-failure]}}

 :statechart/properties
 [{:property/name :exactly-one-signature
   :property/check ":action/sign-consistency-check requires exactly one..."}
  ;; NEW PROPERTY:
  {:property/name :policy-enforced-before-start
   :property/check ":state/starting is strictly unreachable unless :event/begin-authorized is emitted from the PDP evaluation in :state/begin-authorization."}]}
```

### Implementing the Backend Hook
To wire this up to your `chart_driven.clj` FSM engine, your `:action/dispatch-begin-policy-evaluation` simply needs to invoke the Trivial PDP. 

For example, using the action handler:
```clojure
(defmethod action/invoke :action/dispatch-begin-policy-evaluation
  [_ env context]
  ;; In a real implementation this might be async.
  ;; For the trivial PDP, we immediately queue the evaluation result.
  (let [decision (evaluate-pdp :permit-all context)]
    (if (:authorized? decision)
      (fsm/queue-event! env {:type :event/begin-authorized})
      ;; Using fsm/assign to update context if rejected, then queueing rejection event
      (do
        (fsm/assign! env :policy/rejection-reason (:reason decision))
        (fsm/queue-event! env {:type :event/begin-rejected})))))
```

### Conclusion
By treating policy checks as explicit transition nodes rather than guarded conditions, you've ensured that future complexity (like Datalog or OPA policies) does not corrupt the lifecycle logic. This strategy will allow Figure, the Independent Custodian, and the Holder to gracefully execute independent verification passes while strictly abiding by the rules of the statechart.