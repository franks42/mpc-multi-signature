(ns smoke-chart-driven-presign
  "Smoke runner: drive presign via the executable chart, then sign with
   the resulting presig-handle. Cross-verify the signature against the
   wallet pubkey from keygen.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven-presign"
  (:require [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        _ (println "started:"
                   {:identity-pubkeys (:identity-pubkeys o)
                    :participant-ids  (:participant-ids o)})

        ;; Setup: keygen + triple-gen procedurally so we have inputs
        ;; for the chart-driven presign.
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg) (str "keygen failed: " kg))
        share-handle (:share-handle kg)
        original-pk  (:public-key kg)

        triple (orch/triple-generation o [:holder :figure]
                                       {:share-handle share-handle})
        _ (assert (:triple-handle triple)
                  (str "triple-gen failed: " triple))

        ;; CHART-DRIVEN presign.
        presig (cd/run-presign-via-chart
                o [:holder :figure]
                {:share-handle  share-handle
                 :triple-handle (:triple-handle triple)})
        _ (assert (:presig-handle presig)
                  (str "chart-driven presign failed: " presig))
        _ (println "chart-driven presign done: presig-handle="
                   (:presig-handle presig))

        ;; Sign procedurally with the chart-derived presig.
        digest "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        sign-result (orch/sign o [:holder :figure]
                               {:coordinator   :figure
                                :share-handle  share-handle
                                :presig-handle (:presig-handle presig)
                                :digest-hex    digest})
        _ (assert (:signature-hex sign-result)
                  (str "sign failed: " sign-result))

        verified? (orch/cross-verify-signature original-pk digest
                                               (:signature-hex sign-result))
        _ (assert verified?
                  "signature did not verify against original pubkey")]
    (println)
    (println "smoke OK")
    (println "  chart-driven presig :" (:presig-handle presig))
    (println "  sign cross-verified :" verified?)
    (println "  → executable presign chart drives a real ceremony")
    (println "    end-to-end. The resulting presig-handle is consumable")
    (println "    by sign and produces a signature verifying under the")
    (println "    original wallet public key.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
