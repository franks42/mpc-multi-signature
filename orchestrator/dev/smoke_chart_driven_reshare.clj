(ns smoke-chart-driven-reshare
  "Smoke runner: drive a reshare via the executable chart, then sign
   with the resulting shareset. Cross-verify the signature against
   the ORIGINAL wallet pubkey — the load-bearing UC2 invariant.

   Exercises the divorce-style variant (membership changes) because
   it's the most interesting: old-peers ≠ new-peers tests both the
   protocol-runners-only-new logic and the public-key preservation
   check.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven-reshare"
  (:require [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})

        ;; 1. Initial 3-party keygen.
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg) (str "keygen failed: " kg))
        original-pk  (:public-key kg)
        _ (println "keygen done: pk=" (subs original-pk 0 12) "...")

        ;; 2. CHART-DRIVEN reshare — divorce-style: holder leaves;
        ;;    new shareset is just [figure, ic].
        reshared (cd/run-reshare-via-chart
                  o
                  {:old-participants [:holder :figure :ic]
                   :new-participants [:figure :ic]
                   :old-share-handle (:share-handle kg)
                   :public-key-hex   original-pk})
        _ (assert (:share-handle reshared)
                  (str "chart-driven reshare failed: " reshared))
        _ (assert (= (:public-key reshared) original-pk)
                  (str "PUBLIC-KEY DRIFT: original=" original-pk
                       " reshared=" (:public-key reshared)))
        _ (println "chart-driven reshare done:")
        _ (println "  pk preserved        :" (= (:public-key reshared) original-pk))
        _ (println "  new share-handle    :" (:share-handle reshared))
        _ (println "  new shareset roles  :" (sort (keys (:handles reshared))))

        ;; 3. Sign with new shareset (figure + ic, both new participants).
        triple (orch/triple-generation o [:figure :ic]
                                       {:share-handle (:share-handle reshared)})
        _ (assert (:triple-handle triple))

        presig (orch/presign o [:figure :ic]
                             {:share-handle  (:share-handle reshared)
                              :triple-handle (:triple-handle triple)})
        _ (assert (:presig-handle presig))

        digest "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        sign-result (orch/sign o [:figure :ic]
                               {:coordinator   :figure
                                :share-handle  (:share-handle reshared)
                                :presig-handle (:presig-handle presig)
                                :digest-hex    digest})
        _ (assert (:signature-hex sign-result))

        ;; 4. Cross-verify against the ORIGINAL wallet pubkey.
        verified? (orch/cross-verify-signature original-pk digest
                                               (:signature-hex sign-result))
        _ (assert verified?
                  "signature from new shareset did not verify against original pubkey")]
    (println)
    (println "smoke OK")
    (println "  reshared pk          :" (subs (:public-key reshared) 0 24) "...")
    (println "  new shareset signed  : true")
    (println "  cross-verified       :" verified?)
    (println "  → executable reshare chart drives the load-bearing")
    (println "    UC2 mechanism: post-reshare shareset signs and the")
    (println "    signature verifies under the ORIGINAL wallet pubkey.")
    (println "    The same chart covers recovery, refresh, and divorce")
    (println "    variants — only the begin-message payload differs.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
