(ns smoke-refresh-divorce
  "Stage 0.5+ smoke: exercise the refresh and divorce wrapper
   ceremonies end-to-end on top of the existing reshare-recovery
   plumbing.

   Flow:
     1. keygen  [holder, figure, ic]                       — initial wallet
     2. refresh [holder, figure, ic]                       — same membership, fresh polynomial
     3. triple-gen + presign + sign  [holder, figure]      — confirm refreshed shares still sign for original pubkey
     4. divorce — remove figure                            — new shareset = [holder, ic]
     5. (smoke ends here; signing under a 2-of-2 between holder + ic
        would require building presigs against the new shareset which
        is the same code path as today, just with different
        participants — exercising it here doesn't add information)

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-refresh-divorce"
  (:require [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        _ (println "started:" {:identity-pubkeys (:identity-pubkeys o)})

        ;; --- 1. keygen ---
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg) (str "keygen failed: " kg))
        original-pk (:public-key kg)
        _  (println "keygen done: pk=" (subs original-pk 0 12) "...")

        ;; --- 2. refresh (same membership) ---
        refreshed (orch/refresh o {:participants     [:holder :figure :ic]
                                   :old-share-handle (:share-handle kg)
                                   :public-key-hex   original-pk})
        _ (assert (:share-handle refreshed)
                  (str "refresh failed: " refreshed))
        _ (assert (= (:public-key refreshed) original-pk)
                  (str "refresh: pk drifted! "
                       {:original original-pk :got (:public-key refreshed)}))
        _ (println "refresh done: same pk, fresh share-handle="
                   (str (:share-handle refreshed)))

        ;; --- 3. sign with refreshed shareset (holder + figure) ---
        triple-handle (-> (orch/triple-generation o [:holder :figure]
                                                  {:share-handle (:share-handle refreshed)})
                          :triple-handle)
        presig-handle (-> (orch/presign o [:holder :figure]
                                        {:share-handle  (:share-handle refreshed)
                                         :triple-handle triple-handle})
                          :presig-handle)
        digest "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        sign-result (orch/sign o [:holder :figure]
                               {:coordinator   :figure
                                :share-handle  (:share-handle refreshed)
                                :presig-handle presig-handle
                                :digest-hex    digest})
        _ (assert (:signature-hex sign-result)
                  (str "sign-with-refreshed failed: " sign-result))
        verified? (orch/cross-verify-signature original-pk digest
                                               (:signature-hex sign-result))
        _ (assert verified?
                  "sign-with-refreshed: signature did not verify against original pubkey")
        _ (println "sign with refreshed shareset: signature verified ✓")

        ;; --- 4. divorce: remove figure, no replacement (2-of-2) ---
        divorced (orch/divorce o {:old-participants [:holder :figure :ic]
                                  :removed-party    :figure
                                  :old-share-handle (:share-handle refreshed)
                                  :public-key-hex   original-pk})
        _ (assert (:share-handle divorced)
                  (str "divorce failed: " divorced))
        _ (assert (= (:public-key divorced) original-pk)
                  (str "divorce: pk drifted! "
                       {:original original-pk :got (:public-key divorced)}))
        new-handles (:handles divorced)
        _ (assert (= #{:holder :ic} (set (keys new-handles)))
                  (str "divorce: expected new shareset {holder ic}, got "
                       (keys new-handles)))]
    (println "divorce done: figure removed, new shareset members="
             (sort (keys new-handles)) "pk preserved")
    (println)
    (println "smoke OK"
             {:keygen-pk    (subs original-pk 0 16)
              :refresh-pk   (subs (:public-key refreshed) 0 16)
              :divorce-pk   (subs (:public-key divorced) 0 16)
              :sign-with-refreshed :verified})
    (orch/stop-orchestrator o)
    (System/exit 0)))
