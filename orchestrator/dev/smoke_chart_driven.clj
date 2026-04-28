(ns smoke-chart-driven
  "Smoke runner for the chart-driven runtime.

   Drives triple-generation through chart_driven (which targets the
   executable chart at specs/executable/statechart-triple-generation.edn)
   and verifies the chart-driven triple-handle is consumable by subsequent
   presign + sign — i.e. the chart-driven path produces a real,
   protocol-correct triple, not a structural artifact.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven"
  (:require [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        _ (println "started:"
                   {:identity-pubkeys (:identity-pubkeys o)
                    :participant-ids  (:participant-ids o)})

        ;; 1. keygen (procedural) so we have a share-handle to feed
        ;; the triple-gen ceremony.
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg) (str "keygen failed: " kg))
        share-handle (:share-handle kg)
        original-pk  (:public-key kg)
        _ (println "keygen done: pk=" (subs original-pk 0 12) "...")

        ;; 2. triple-generation via chart-driven.
        triple (cd/run-triple-generation-via-chart
                o [:holder :figure]
                {:share-handle share-handle})
        _ (assert (:triple-handle triple)
                  (str "chart-driven triple-generation failed: " triple))
        _ (println "chart-driven triple-gen done: triple-handle="
                   (:triple-handle triple))

        ;; 3. exercise the chart-driven triple via presign + sign.
        presig (orch/presign o [:holder :figure]
                             {:share-handle  share-handle
                              :triple-handle (:triple-handle triple)})
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
    (println "  chart-driven triple :" (:triple-handle triple))
    (println "  presign on triple      :" (:presig-handle presig))
    (println "  sign cross-verified    :" verified?)
    (println "  → executable chart drives a real triple-gen ceremony")
    (println "    end-to-end, producing a signature that verifies")
    (println "    under the original wallet public key.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
