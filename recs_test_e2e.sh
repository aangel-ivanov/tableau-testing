#!/bin/sh

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SCRIPT_SHORTNAME=`basename "$0"`
HOSTNAME=$( hostname -s )

export ONLINE_USER_READONLY=readonly
export ONLINE_USER_READONLY_PWRD=
export ONLINE_USER_READONLY_HASH=1001170

echo
echo ===============================================================
echo === TESTS on $HOSTNAME
echo ===============================================================
echo
echo $SCRIPT_DIR/$SCRIPT_SHORTNAME $*

if [ -z "$SERVERURL" ]; then
  export SERVERURL=http://$HOSTNAME
fi
if [ -z "$SITE" ]; then
  export SITE=Recommendations
fi
if [ -z "$PERSONAL_TOKEN_NAME" ]; then
  export PERSONAL_TOKEN_NAME=default
fi
if [ -z "$PERSONAL_TOKEN_VALUE" ]; then
  export PERSONAL_TOKEN_VALUE=default
fi
if [ -z "$FORCE_UPDATE_SITE" ]; then
  export FORCE_UPDATE_SITE=0
fi
if [ -z "$FORCE_UPDATE_PROJ" ]; then
  export FORCE_UPDATE_PROJ=0
fi

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -t|--server)
      SERVERURL="$2"
      shift
      shift
      ;;
    -s|--site-name)
      SITE="$2"
      shift
      shift
      ;;
    -tn|--personal-token-name)
      PERSONAL_TOKEN_NAME="$2"
      shift
      shift
      ;;
    -tv|--personal-token-value)
      PERSONAL_TOKEN_VALUE="$2"
      shift
      shift
      ;;
    -f|--delete-site)
      VALUE=$2
      if [ "${VALUE:0:2}" = "--" ] || [ "$VALUE" = "" ]; then
        FORCE_UPDATE_SITE=1
      else
        FORCE_UPDATE_SITE=$VALUE
        shift
      fi
      shift
      ;;
    -p|--delete-project)
      VALUE=$2
      if [ "${VALUE:0:2}" = "--" ] || [ "$VALUE" = "" ]; then
        FORCE_UPDATE_PROJ=1
      else
        FORCE_UPDATE_PROJ=$VALUE
        shift
      fi
      shift
      ;;
    --default)
      DEFAULT=YES
      shift
      ;;
    *)
      POSITIONAL+=("$1") # save it in an array for later
      shift
      ;;
  esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z "$SERVERURL" ] || [ "$SERVERURL" = "" ]; then
    echo && echo "Server name not specified. Aborting..."
    exit -1
fi

if [ "$FORCE_UPDATE_SITE" = "1" ]; then
    export FORCE_UPDATE_PROJ=1
fi

echo
echo This script will use the following env variables:
echo SERVERURL=$SERVERURL
echo SITE=$SITE
echo PERSONAL_TOKEN_NAME=$PERSONAL_TOKEN_NAME
echo PERSONAL_TOKEN_VALUE=$PERSONAL_TOKEN_VALUE
echo FORCE_UPDATE_SITE=$FORCE_UPDATE_SITE
echo FORCE_UPDATE_PROJ=$FORCE_UPDATE_PROJ
echo ONLINE_USER_READONLY=$ONLINE_USER_READONLY
echo ONLINE_USER_READONLY_HASH=$ONLINE_USER_READONLY_HASH

echo
echo ===============================================================
echo == CONTENT, VIEWS $SITE on $SERVERURL
echo ===============================================================
echo

rc=True

exists_site()
{
  echo && echo python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --exists-site
  echo
  
  rc=$(python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --exists-site | egrep True | wc -l | bc)

  if [ $rc -eq 1 ]; then
    rc=True
  else
    rc=False
  fi

  echo $rc
  export $rc
}

exists_project()
{
  echo && echo python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --exists-project
  echo
  
  rc=$(python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --exists-project | egrep "True" | wc -l |bc)
  
  if [ $rc -eq 1 ]; then
    rc=True
  else
    rc=False
  fi

  echo $rc
  export $rc
}

create_site()
{
  echo && echo python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --create-site
  echo

  python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --create-site
}

delete_site()
{
  echo && echo python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --delete-site
  echo

  python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --delete-site
}

create_project()
{
  echo && echo python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --project-name $3 --create-project
  echo

  python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --project-name $3 --create-project
}

delete_project()
{
  echo && echo python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --delete-project
  echo

  python testutils.py --server $1 --site-name $2 --project-name $3 --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --delete-project
}

if [ "$FORCE_UPDATE_SITE" = "1" ]; then
  exists_site $SERVERURL $SITE Recommendations
  if [ "$rc" = "True" ]; then
    delete_site $SERVERURL $SITE Recommendations
  fi
  create_site $SERVERURL $SITE Recommendations
fi

exists_site $SERVERURL $SITE Recommendations

if [ "$rc" = "False" ] || [ "$rc" = "" ]; then

  echo "!FAILED: Cannot make sure site $SITE exists. Aborting ..."
  echo
  exit -3

else

  if [ "$FORCE_UPDATE_PROJ" = "1" ]; then
    exists_project $SERVERURL $SITE Recommendations
    if [ "$rc" = "True" ]; then
      delete_project $SERVERURL $SITE Recommendations
    fi
    create_project $SERVERURL $SITE Recommendations
  fi

  exists_project $SERVERURL $SITE Recommendations

  if [ "$rc" = "False" ] || [ "$rc" = "" ]; then
    echo
    echo "!FAILED: The project does not exist. Aborting ... "
    exit -4
  fi

fi

if [ "$rc" = "True" ]; then

  mkdir tmp_$SITE > /dev/null 2>&1
  rm -rf tmp_$SITE/Recommendations > /dev/null 2>&1
  cp -r ../content/Recommendations tmp_$SITE/ > /dev/null 2>&1

  echo
  echo ===============================================================
  echo === Upload and setup content on $SERVERURL
  echo ===============================================================
  echo
  echo python testutils.py --server $SERVERURL --site-name $SITE --project-name Recommendations --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --upload-content --local-directory tmp_$SITE/Recommendations --username-connection \$ONLINE_USER_READONLY  --password-connection $ONLINE_USER_READONLY_HASH
 
  python testutils.py --server $SERVERURL --site-name $SITE --project-name Recommendations --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --upload-content --local-directory tmp_$SITE/Recommendations --username-connection $ONLINE_USER_READONLY  --password-connection $ONLINE_USER_READONLY_PWRD
  
  rm -rf tmp_$SITE > /dev/null 2>&1
  sleep 3

  echo
  echo ===============================================================
  echo === Run simple views on some of the dashboards on $SERVERURL
  echo ===============================================================
  echo

  echo
  sleep 3
  echo python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook DailyResources --dashboard DailyResource --run-viewtests-simple 1
  echo
  python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook DailyResources --dashboard DailyResource --run-viewtests-simple 1
  
  echo
  sleep 3
  echo python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook MonthlyServerStats --dashboard MonthlyServerStats --run-viewtests-simple 1
  echo
  python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook MonthlyServerStats --dashboard MonthlyServerStats --run-viewtests-simple 1
  
  echo
  sleep 3
  echo python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook ServerUsage --dashboard ServerUsage --run-viewtests-simple 1
  echo
  python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook ServerUsage --dashboard ServerUsage --run-viewtests-simple 1
  
  echo
  sleep 3
  echo python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook WorkbookInfo --dashboard WorkbookInfo --run-viewtests-simple 1
  echo
  python testutils.py --server $SERVERURL --site-name $SITE --personal-token-name $PERSONAL_TOKEN_NAME --personal-token-value $PERSONAL_TOKEN_VALUE --workbook WorkbookInfo --dashboard WorkbookInfo --run-viewtests-simple 1

fi

