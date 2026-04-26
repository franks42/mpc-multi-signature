(ns smoke-5b2
  "Stage 5b.2 smoke: handshake + keygen + share-possession (basic) +
   share-possession (binding) + verify-all-binding-share-proofs.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-5b2

   Confirms: each bb wrapper holds its own private Ed25519 key, the
   orchestrator only sees public keys, and the binding signatures
   verify against those public keys."
  (:require [mpc-multi-signature.orchestrator.core :as orch]))

(defn -main [& _]
  (let [o    (orch/start-orchestrator {})
        _    (println "started:"
                      {:identity-pubkeys (:identity-pubkeys o)
                       :participant-ids  (:participant-ids o)})
        kg   (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _    (assert (:share-handle kg)
                     (str "keygen failed: " kg))
        share-handle (:share-handle kg)
        basic (orch/share-possession-proof
               o [:holder :figure :ic]
               {:share-handle          share-handle
                :challenge-context-hex "deadbeef"})
        _     (assert (:proofs basic)
                      (str "basic share-proof failed: " basic))
        basic-check (orch/verify-all-share-proofs basic kg)
        _     (assert (:all-valid? basic-check)
                      (str "basic verify failed: " basic-check))
        binding (orch/binding-share-possession-proof
                 o [:holder :figure :ic]
                 {:share-handle       share-handle
                  :verifier-nonce-hex "0011223344556677"})
        _       (assert (:proofs binding)
                        (str "binding share-proof failed: " binding))
        binding-check (orch/verify-all-binding-share-proofs o binding kg)]
    (assert (:all-valid? binding-check)
            (str "binding verify failed: " binding-check))
    (println "smoke OK"
             {:basic-per-party   (:per-party basic-check)
              :binding-per-party (:per-party binding-check)})
    (orch/stop-orchestrator o)
    (System/exit 0)))
