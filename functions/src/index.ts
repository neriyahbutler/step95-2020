import * as admin from 'firebase-admin';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as config from './config';

// Initialize Firebase
admin.initializeApp(config.firebaseConfig);

import * as CVEFunction from './CVE/index';
import * as SPLFunction from './SPL/index';
import * as bulletinFunction from './bulletin/index';
import * as androidVersionFunction from './Android Version/index';
import * as notificationFunction from './notification/index';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getCVEFunction = CVEFunction.getCVE;
export const getSPLFunction = SPLFunction.getSPL;
export const getBulletinFunction = bulletinFunction.getBulletin;
export const getAndroidVersionFunction = androidVersionFunction.getAndroidVersion;
export const storeEmailFunction = notificationFunction.accountCreate;
export const notifyNewVersionFunction = notificationFunction.notifyNewVersion;
export const notifyNewReleaseFunction = notificationFunction.notifyNewRelease;
