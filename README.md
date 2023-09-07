# pc-ds-updater
# Edit and rename credentials.json.empty to credentials.json

`./add_credential.sh`  # (must have kubectl installed)
   # or  
    `kubectl create -n twistlock secret generic pcc-secrets --from-file=credentials.json`

# Don't need the credential.json after you add the credentials

`kubectl apply -f ds_manager_role.yaml`
`kubectl apply -f defender_options.yaml` # These are static options you want to persist for your daemonset. Overwrites what comes from the api
`kubectl apply -f updater_rs.yaml`
