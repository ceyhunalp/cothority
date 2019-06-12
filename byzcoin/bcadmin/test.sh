#!/usr/bin/env bash

# Usage: 
#   ./test [options]
# Options:
#   -b   re-builds bcadmin package

DBG_TEST=1
DBG_SRV=1
DBG_BCADMIN=1

NBR_SERVERS=4
NBR_SERVERS_GROUP=3

# Clears some env. variables
export -n BC_CONFIG
export -n BC

. "../../libtest.sh"
. "../clicontracts/config_test.sh"
. "../clicontracts/deferred_test.sh"
. "../clicontracts/value_test.sh"

main(){
    startTest
    buildConode go.dedis.ch/cothority/v3/byzcoin go.dedis.ch/cothority/v3/byzcoin/contracts
    [[ ! -x ./bcadmin ]] && exit 1
    run testReplay
    run testLink
    run testLinkScenario
    run testCoin
    run testRoster
    run testCreateStoreRead
    run testAddDarc
    run testDarcAddDeferred
    run testDarcAddRuleMinimum
    run testRuleDarc
    run testAddDarcFromOtherOne
    run testAddDarcWithOwner
    run testExpression
    run testLinkPermission
    run testQR
    run testUpdateDarcDesc
    run testContractValue
    run testContractDeferred
    run testContractConfig
    stopTest
}

testReplay(){
  rm -f config/*
  runCoBG 1 2 3
  runBA create public.toml --interval .5s
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  bc=config/bc*cfg
  key=config/key*cfg
  keyPub=$( echo $key | sed -e "s/.*:\(.*\).cfg/\1/" )
  testOK runBA debug replay http://localhost:2003

  # replay with only the genesis block
  testOK runBA debug replay http://localhost:2003 $bcID

  for i in $( seq 10 ); do
    runBA mint $bc $key $keyPub 1000
  done
  # replay with more than 1 block
  testOK runBA debug replay http://localhost:2003 $bcID
}

testLink(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  runBA key --save newkey.id
  testOK runBA darc add --bc $bc --owner $( cat newkey.id ) --out_id darc.id

  rm -rf linkDir
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  testGrep $bcID runBA -c linkDir link public.toml
  bcIDWrong=$( printf "%032d" 1234 )
  testNGrep $bcIDWrong runBA -c linkDir link public.toml
  testFail runBA -c linkDir link public.toml $bcIDWrong
  testOK runBA -c linkDir link --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID
  testFile linkDir/bc*
}

# This is a complete scenario with link that uses the value clicontract.
# We create a new client and a new associated darc that is allowed to call
# "spawn:value". We first need to specify --darc and --sign to use the value
# contract. But then we link to the client and its darc, which will then use
# by default the client's identity and darc.
testLinkScenario(){
  rm -f config/*
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  # Create new client
  runBA key --save newkey.id
  # Create new darc for the client
  testOK runBA darc add --owner $( cat newkey.id ) --out_id darc.id --unrestricted

  # Try to spawn a new value contract with the client's darc. It should fail
  # since we did not add the rule
  testFail runBA contract value spawn --value "should fail" --darc $( cat darc.id ) --sign $( cat newkey.id )

  # Update the client darc so that it can spawn:value new contracts
  testOK runBA darc rule --rule "spawn:value" --identity $( cat newkey.id ) --sign $( cat newkey.id ) --darc $( cat darc.id )

  # Try to spawn again, should work this time
  testOK runBA contract value spawn --value "shoudl fail" --darc $( cat darc.id ) --sign $( cat newkey.id )

  # Now if we don't specify any --darc and --sign, it will use the admin darc,
  # which should fail since it doesn't have the rule
  testFail runBA contract value spawn --value "should fail"

  # Let's try now to link with the client darc and identity. This will make that
  # default --darc and --sign will be the client's darc and identiity
  bcID=$( echo $BC | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  testOK runBA link --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID
  # The final test
  testOK runBA contract value spawn --value "shoud pass"

  testOK unset BC
}

testCoin(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  keyPub=$( echo $key | sed -e "s/.*key-ed25519:\(.*\).cfg/\1/" )
  testOK runBA mint $bc $key $keyPub 10000
}

testRoster(){
  rm -f config/*
  runCoBG 1 2 3 4
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  testOK runBA latest $bc
  # Adding an already added roster should raise an error
  testFail runBA roster add $bc $key co1/public.toml
  testOK runBA roster add $bc $key co4/public.toml

  # Change the block size to create a new block before verifying the roster
  testOK runBA config --blockSize 1000000 $bc $key
  testGrep 2008 runBA latest $bc

  testFail runBA roster add $bc $key co4/public.toml
  # Deleting the leader raises an error...
  testFail runBA roster del $bc $key co1/public.toml
  # ... but deleting someone else works
  testOK runBA roster del $bc $key co2/public.toml
  # Change the block size to create a new block before verifying the roster
  testOK runBA config --blockSize 1000000 $bc $key
  sleep 10

  testNGrep "Roster:.*tls://localhost:2004" runBA latest $bc
  # Need at least 3 nodes to have a majority
  testFail runBA roster del $bc $key co3/public.toml
  # Adding a leader not in the roster raises an error
  testFail runBA roster leader $bc $key co2/public.toml
  # Setting a conode that is a leader as a leader raises an error
  testFail runBA roster leader $bc $key co1/public.toml
  testOK runBA roster leader $bc $key co3/public.toml
  # Change the block size to create a new block before verifying the roster
  testOK runBA config --blockSize 1000000 $bc $key
  testGrep "Roster: tls://localhost:2006" runBA latest -server 2 $bc
}


# When a conode is linked to a client (`scmgr link add ...`), it removes the
# possibility for 3rd parties to create a new skipchain on that conode. In the
# case a Bizcoin service hosted on a linked conode wants to adds a new
# skipchain, we have to bypass this authorization process and allow a local
# service be able to send requests on the same local linked conode. This process
# is handled with the `StoreSkipBlockInternal` method, and this is what this
# method checks. 
# Note: this test relies on the `scmgr` and the ability to create/update Byzcoin
testLinkPermission() {
  rm -f config/*
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1
  bc=config/bc*cfg
  key=config/key*cfg
  testOK runBA latest $bc
  build $APPDIR/../../scmgr
  SCMGR_APP="./scmgr"
  if [ ! -x $SCMGR_APP ]; then
    echo "Didn't find the \"scmgr\" executable at $SCMGR_APP"
    exit 1
  fi
  $SCMGR_APP link add co1/private.toml
  $SCMGR_APP link add co2/private.toml
  $SCMGR_APP link add co3/private.toml
  testOK runBA create --roster public.toml --interval .5s
  testOK runBA darc rule -rule spawn:xxx -identity ed25519:aef 
}


# create a ledger, and read the genesis darc.
testCreateStoreRead(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1
  bcid=`echo $BC | awk -F- '{print $2}'| sed 's/.cfg$//'`
  testGrep "ByzCoinID: $bcid" runBA latest
}

testAddDarc(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add
  testOK runBA darc add -out_id ./darc_id.txt
  testOK runBA darc add
  ID=`cat ./darc_id.txt`
  testGrep "${ID:5:${#ID}-0}" runBA darc show --darc "$ID"
}

testDarcAddDeferred() {
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  # standard stuff
  testOK runBA darc adeferred
  testOK runBA darc adeferred -out_id ./darc_id.txt
  testOK runBA darc adeferred
  ID=`cat ./darc_id.txt`
  testGrep "${ID:5:${#ID}-0}" runBA darc show --darc "$ID"
  testGrep "spawn:deferred" runBA darc show --darc "$ID"
  testGrep "invoke:deferred.addProof" runBA darc show --darc "$ID"
  testGrep "invoke:deferred.execProposedTx" runBA darc show --darc "$ID"

  # more advanced
  testOK runBA darc adeferred -id darc:A -id ed25519:B -id darc:C -id darc:D -out_id ./darc_id.txt
  ID=`cat ./darc_id.txt`
  testGrep "spawn:deferred - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA darc show --darc "$ID"
  testGrep "invoke:deferred.addProof - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA darc show --darc "$ID"
  testGrep "invoke:deferred.execProposedTx - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA darc show --darc "$ID"
}

testDarcAddRuleMinimum(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  # With M out of N
  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id darc:A -id darc:B -id darc:C -id darc:D --minimum 1
  testFGrep "test:contract - \"((darc:A)) | ((darc:B)) | ((darc:C)) | ((darc:D))\"" runBA darc show --darc "$ID"
  
  # with a minimum
  testOK runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id darc:A -id darc:B -id darc:C -id darc:D --minimum 2 -replace
  testFGrep "test:contract - \"((darc:A) & (darc:B)) | ((darc:A) & (darc:C)) | ((darc:A) & (darc:D)) | ((darc:B) & (darc:C)) | ((darc:B) & (darc:D)) | ((darc:C) & (darc:D))\"" runBA darc show --darc "$ID"

  # with a minimum and a special id composed of an AND
  testOK runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'darc:A & ed25519:aef' -id darc:B -id darc:C -id darc:D --minimum 2 -replace
  testFGrep "test:contract - \"((darc:A & ed25519:aef) & (darc:B)) | ((darc:A & ed25519:aef) & (darc:C)) | ((darc:A & ed25519:aef) & (darc:D)) | ((darc:B) & (darc:C)) | ((darc:B) & (darc:D)) | ((darc:C) & (darc:D))\"" runBA darc show --darc "$ID"

  # with some wrong identities
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'xdarc:A & ed25519:aef' -id darc:B --minimum 2 -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'xdarc:A & ed25519:aef' -id darc:B -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'ed25519:aef &' -id darc:B --minimum 2 -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'darc:A & C & ed25519:aef' -id darc:B -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id ' ' -id darc:B --minimum 2 -replace
}

testRuleDarc(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -desc testing -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testGrep "Description: \"testing\"" runBA darc show -darc $ID
  testOK runBA darc rule -rule spawn:xxx -identity ed25519:abc -darc "$ID" -sign "$KEY"
  testGrep "spawn:xxx - \"ed25519:abc\"" runBA darc show -darc "$ID"
  testOK runBA darc rule -replace -rule spawn:xxx -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"
  testGrep "spawn:xxx - \"ed25519:abc | ed25519:aef\"" runBA darc show -darc "$ID"
  testOK runBA darc rule -delete -rule spawn:xxx -darc "$ID" -sign "$KEY"
  testNGrep "spawn:xxx" runBA darc show -darc "$ID"
}

testAddDarcFromOtherOne(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add -out_key ./key.txt -out_id ./id.txt -unrestricted
  KEY=`cat ./key.txt`
  ID=`cat ./id.txt`
  testOK runBA darc rule -rule spawn:darc -identity "$KEY" -darc "$ID" -sign "$KEY"
  testOK runBA darc add -darc "$ID" -sign "$KEY"
}

testAddDarcWithOwner(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA key -save ./key.txt
  KEY=`cat ./key.txt`
  testOK runBA darc add -owner "$KEY" -out_id "darc_id.txt"
  ID=`cat ./darc_id.txt`
  testGrep "$KEY" runBA darc show -darc "$ID"
}

testExpression(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA key -save ./key.txt
  KEY2=`cat ./key.txt`

  testOK runBA darc rule -rule spawn:darc -identity "$KEY | $KEY2" -darc "$ID" -sign "$KEY"
  testOK runBA darc show -darc "$ID"
  testOK runBA darc add -darc "$ID" -sign "$KEY"
  testOK runBA darc add -darc "$ID" -sign "$KEY2"

  testOK runBA darc rule -replace -rule spawn:darc -identity "$KEY & $KEY2" -darc "$ID" -sign "$KEY"
  testFail runBA darc add -darc "$ID" -sign "$KEY"
  testFail runBA darc add -darc "$ID" -sign "$KEY2"
}

runBA(){
  ./bcadmin -c config/ --debug $DBG_BCADMIN "$@"
}

testQR() {
  runCoBG 1 2 3
  runGrepSed "export BC=" "" ./"$APP" create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK ./"$APP" qr -admin
}

testUpdateDarcDesc() {
  # We update the description of the latest darc, then we get the latest darc
  # and check if the description changed.
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc cdesc --desc "New description"
  testGrep "New description" runBA darc show

  # Same test, but with a restricted darc
  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -desc testing
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA darc cdesc --desc "New description" --darc "$ID"
  testGrep "New description" runBA darc show
}

main

