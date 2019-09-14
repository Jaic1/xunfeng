#!/bin/bash
CURRENT_PATH=`dirname $0`
cd $CURRENT_PATH

XUNFENG_LOG=/var/log/xunfeng
XUNFENG_DB=/var/lib/mongodb

[ ! -d $XUNFENG_LOG ] && mkdir -p ${XUNFENG_LOG}
[ ! -d $XUNFENG_DB ] && mkdir -p ${XUNFENG_DB}

nohup mongod --port 27017 --dbpath=${XUNFENG_DB} --auth  > ${XUNFENG_LOG}/db.log 2>&1 &
nohup python web.py  > ${XUNFENG_LOG}/web.log 2>&1 &
nohup python aider/aider.py > ${XUNFENG_LOG}/aider.log 2>&1 &
nohup python nascan/nascan.py > ${XUNFENG_LOG}/scan.log 2>&1 &
nohup python vulscan/vulscan.py > ${XUNFENG_LOG}/vul.log 2>&1 &
