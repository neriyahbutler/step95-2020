import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as admin from 'firebase-admin';
import * as checks from '../errorChecks';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getSPL = functions.https.onRequest(main);

app.get('/spls', (request, response) => {

  const bulletinID = request.query.bulletinid;
  const androidVersion = request.query.androidVersion;

  if (bulletinID) {
    if (!checks.checkBulletinIDValidity(bulletinID)) {
      response.status(400).send("Error: Bulletin ID is malformed.");
    }
    getSplsWithBulletinID(String(bulletinID), response);
  }
  else if (androidVersion) {
    if (!checks.checkAndroidVersionValidity(androidVersion)) {
      response.status(400).send("Error: Android Version ID is malformed.");
    }
    getSplsWithAndroidVersion(String(androidVersion), response);
  }

});

function getSplsWithBulletinID(id: string, res: any) {
  ;
  const db = admin.database();
  const ref = db.ref('/Bulletin_SPL');
  let splData: any;
  ref.orderByKey().equalTo(id).once('value', function (snapshot) {
    splData = snapshot.val();
    if (splData === null || splData === undefined) {
      res.status(404).send("Error: There is no SPL data associated with this bulletin in the database.");
    }
    const splOutput = { Spls: splData[id] }
    res.send(splOutput);
  }).catch(error => {
    res.status(500).send("error getting spls for bulletinID: " + error)
  });
}

function getSplsWithAndroidVersion(version: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
  let bulletinData: any;
  const aospVerToBulletinPromise = ref.orderByKey().equalTo(version).once('value')
  const bulletinSplPromise = aospVerToBulletinPromise.then((snapshot) => {
    bulletinData = snapshot.val();
    if (bulletinData === null || bulletinData === undefined) {
      res.status(404).send("Error: There are no SPLs associated with this Android Version ID in the database.");
    }
    const promises = [];
    for (const bulletinID of Object.keys(bulletinData[version])) {
      const splPromise = db.ref('/Bulletin_SPL').orderByKey().equalTo(bulletinID).once('value');
      promises.push(splPromise);
    }
    return Promise.all(promises);
  });
  bulletinSplPromise.then((bulletinSpls) => {
    const splArray = [];
    const bulletinIDs = Object.keys(bulletinData[version]);
    for (let i = 0; i < bulletinSpls.length; i++) {
      const bulletinSplObject = bulletinSpls[i].val();
      const spls = bulletinSplObject[bulletinIDs[i]];
      for (const spl of spls) {
        splArray.push(spl);
      }
    }
    const splOutput = { Spls: splArray };
    res.send(splOutput);
  }).catch(error => {
    res.status(500).send("error getting spls for AndroidVersion: " + error)
  });
}


