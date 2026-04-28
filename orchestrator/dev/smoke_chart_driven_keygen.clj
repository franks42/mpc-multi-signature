(ns smoke-chart-driven-keygen
  "Smoke runner: drive keygen via the executable chart, then exercise
   the resulting shareset through procedural triple-gen + presign +
   sign. Cross-verify the signature against the public key reported
   by the chart-driven keygen.

   This is the 'eat the pudding' test — proves the chart-driven
   pattern generalizes from triple-gen (the original POC) to keygen
   (3 parties, real consistency check at finalization).

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven-keygen"
  (:require [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        _ (println "started:"
                   {:identity-pubkeys (:identity-pubkeys o)
                    :participant-ids  (:participant-ids o)})

        ;; 1. CHART-DRIVEN keygen — 3 parties, real consistency check.
        kg (cd/run-keygen-via-chart o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg) (str "chart-driven keygen failed: " kg))
        _  (assert (:public-key kg)   "chart-driven keygen returned no public-key")
        _  (assert (= 3 (count (:verification-shares kg)))
                   "chart-driven keygen missing verification shares")
        share-handle (:share-handle kg)
        original-pk  (:public-key kg)
        _ (println "chart-driven keygen done:")
        _ (println "  pk            =" (subs original-pk 0 12) "...")
        _ (println "  share-handle  =" share-handle)
        _ (println "  vshares roles =" (sort (keys (:verification-shares kg))))

        ;; 2. Procedural triple-gen on the chart-derived shareset.
        triple (orch/triple-generation o [:holder :figure]
                                       {:share-handle share-handle})
        _ (assert (:triple-handle triple)
                  (str "triple-gen on chart-driven shareset failed: " triple))

        ;; 3. Procedural presign + sign.
        presig (orch/presign o [:holder :figure]
                             {:share-handle  share-handle
                              :triple-handle (:triple-handle triple)})
        _ (assert (:presig-handle presig)
                  (str "presign failed: " presig))

        digest "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        sign-result (orch/sign o [:holder :figure]
                               {:coordinator   :figure
                                :share-handle  share-handle
                                :presig-handle (:presig-handle presig)
                                :digest-hex    digest})
        _ (assert (:signature-hex sign-result)
                  (str "sign failed: " sign-result))

        ;; 4. Cross-verify against the chart-driven keygen's public key.
        verified? (orch/cross-verify-signature original-pk digest
                                               (:signature-hex sign-result))
        _ (assert verified?
                  "signature did not verify against chart-driven keygen pubkey")]
    (println)
    (println "smoke OK")
    (println "  chart-driven keygen pk :" (subs original-pk 0 24) "...")
    (println "  triple-handle          :" (:triple-handle triple))
    (println "  presig-handle          :" (:presig-handle presig))
    (println "  sign cross-verified    :" verified?)
    (println "  → executable keygen chart drives a real 3-party DKG")
    (println "    end-to-end. The resulting shareset is usable by the")
    (println "    rest of the procedural ceremony suite, and its")
    (println "    public key is the continuity anchor against which")
    (println "    a sign output cross-verifies.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
