(ns smoke-chart-driven-sign
  "Smoke runner: drive sign via the executable chart. Tests the
   asymmetric-result handling — only the coordinator returns a
   signature; non-coordinators return nil. Cross-verify the resulting
   signature against the wallet pubkey from keygen.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven-sign"
  (:require [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg))
        share-handle (:share-handle kg)
        original-pk  (:public-key kg)

        triple (orch/triple-generation o [:holder :figure]
                                       {:share-handle share-handle})
        _ (assert (:triple-handle triple))

        presig (orch/presign o [:holder :figure]
                             {:share-handle  share-handle
                              :triple-handle (:triple-handle triple)})
        _ (assert (:presig-handle presig))

        ;; CHART-DRIVEN sign with figure as coordinator.
        digest "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        sign-result (cd/run-sign-via-chart
                     o [:holder :figure]
                     {:coordinator   :figure
                      :share-handle  share-handle
                      :presig-handle (:presig-handle presig)
                      :digest-hex    digest})
        _ (assert (:signature-hex sign-result)
                  (str "chart-driven sign failed: " sign-result))
        _ (assert (= :figure (:coordinator sign-result))
                  "result missing or wrong :coordinator")
        _ (println "chart-driven sign done: sig=" (subs (:signature-hex sign-result) 0 16) "...")

        verified? (orch/cross-verify-signature original-pk digest
                                               (:signature-hex sign-result))
        _ (assert verified?
                  "signature did not verify against wallet pubkey")]
    (println)
    (println "smoke OK")
    (println "  chart-driven signature :" (subs (:signature-hex sign-result) 0 24) "...")
    (println "  coordinator            :" (:coordinator sign-result))
    (println "  cross-verified         :" verified?)
    (println "  → executable sign chart drives a real ECDSA sign")
    (println "    end-to-end with asymmetric result handling: only")
    (println "    the coordinator's signature counts; the consistency")
    (println "    check rejects results where 0 or >1 parties signed.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
