(ns smoke-chart-driven
  "Smoke runner: drive triple-generation through both the procedural
   path (orchestrator.core/triple-generation) and the chart-driven path
   (chart-driven-ceremonies/run-triple-generation-via-chart) on the
   same wallet setup. Verify both produce equivalent results and that
   subsequent presign + sign succeed using the chart-driven triple's
   handle.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven"
  (:require [mpc-multi-signature.orchestrator.chart-driven-ceremonies :as cdc]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        _ (println "started:"
                   {:identity-pubkeys (:identity-pubkeys o)
                    :participant-ids  (:participant-ids o)})

        ;; --- 1. keygen (procedural) ---
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg) (str "keygen failed: " kg))
        share-handle (:share-handle kg)
        original-pk  (:public-key kg)
        _ (println "keygen done: pk=" (subs original-pk 0 12) "...")

        ;; --- 2a. triple-generation via PROCEDURAL path ---
        triple-proc (orch/triple-generation o [:holder :figure]
                                            {:share-handle share-handle})
        _ (assert (:triple-handle triple-proc)
                  (str "procedural triple-generation failed: " triple-proc))
        _ (println "procedural triple-gen done: triple-handle="
                   (:triple-handle triple-proc))

        ;; --- 2b. triple-generation via CHART-DRIVEN path ---
        triple-chart (cdc/run-triple-generation-via-chart
                      o [:holder :figure]
                      {:share-handle share-handle})
        _ (assert (:triple-handle triple-chart)
                  (str "chart-driven triple-generation failed: " triple-chart))
        _ (println "chart-driven triple-gen done: triple-handle="
                   (:triple-handle triple-chart))

        ;; --- 3. exercise the chart-driven triple via presign + sign ---
        presig (orch/presign o [:holder :figure]
                             {:share-handle  share-handle
                              :triple-handle (:triple-handle triple-chart)})
        _ (assert (:presig-handle presig)
                  (str "presign on chart-driven triple failed: " presig))

        digest "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        sign-result (orch/sign o [:holder :figure]
                               {:coordinator   :figure
                                :share-handle  share-handle
                                :presig-handle (:presig-handle presig)
                                :digest-hex    digest})
        _ (assert (:signature-hex sign-result)
                  (str "sign with chart-driven triple failed: " sign-result))
        verified? (orch/cross-verify-signature original-pk digest
                                               (:signature-hex sign-result))
        _ (assert verified?
                  "signature-from-chart-driven-triple did not verify against original pubkey")]
    (println)
    (println "smoke OK")
    (println "  procedural triple   :" (:triple-handle triple-proc))
    (println "  chart-driven triple :" (:triple-handle triple-chart))
    (println "  presign on chart-triple :" (:presig-handle presig))
    (println "  sign cross-verified :" verified?)
    (println "  → chart-driven triple-generation produces a valid")
    (println "    triple that subsequent presign + sign can consume")
    (println "    to produce a signature verifiable under the original")
    (println "    wallet public key.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
