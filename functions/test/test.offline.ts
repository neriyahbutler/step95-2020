import 'mocha';
import * as chai from 'chai';
const assert = chai.assert;
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from "firebase-functions-test";

describe("test ASB api", () => {
  let myFunctions:any, adminInitStub:any;
  const tester = funcTest();

  before(async () => {
    adminInitStub = sinon.stub(admin, "initializeApp");
    myFunctions = await import("../src/index");
  });

  after(() => {
    adminInitStub.restore();
    tester.cleanup();
  });

  describe('getCVEFunctions', () => {

    describe('without query params', () => {

      it('should return 400 bad request', (done) => {

        const req = { query: {} };
        const res = {
          status: (statusCode:any) => {
            console.log(statusCode);
            assert.equal(statusCode, 400);
            done();
          },
          send: (result:any) => {
            assert.equal(result, 'Error: A query parameter is required.');
            done();
          }
        };

        myFunctions.getCVEFunction(req, res);

      });
    });

    describe('getCveWithCveID()', () => {

      describe('with an invalid CVE ID', () => {

        it('should return 400 bad request', (done) => {

          const req = { query: {cveid: '2015-9016'} };
          const res = {
            status: (statusCode:any) => {
              assert.equal(statusCode, 400);
              done();
            },
            send: (result:any) => {
              assert.equal(result, 'Error: CVE ID is malformed.');
              done();
            }
          };

          myFunctions.getCVEFunction(req, res);

        });
      });

      describe('with a non-existent CVE ID', () => {

        it('should return 404 not found', (done) => {

          const req = { query: {cveid: 'CVE-2020-2020'} };
          let res:any;
          const refParam = '/CVEs';
          const idParam = 'CVE-2020-2020';
          const onceParam = 'value';
  
          const databaseStub = sinon.stub();
          const refStub = sinon.stub();
          const orderByKeyStub = sinon.stub();
          const equalToStub = sinon.stub();
          const onceStub = sinon.stub();
          const catchStub = sinon.stub();
    
          Object.defineProperty(admin, 'database', { get: () => databaseStub });
          databaseStub.returns({ ref: refStub });
          refStub.withArgs(refParam).returns({ orderByKey: orderByKeyStub });
          orderByKeyStub.returns({ equalTo: equalToStub });
          equalToStub.withArgs(idParam).returns({ once: onceStub });
          onceStub.withArgs(onceParam,function(snap:any){
            snap = {
              val: () => ''
            };
            res = {
              status: (statusCode:any) => {
                console.log(statusCode);
                assert.equal(statusCode, 404);
                done();
              },
              send: (result:any) => {
                assert.equal(result, 'Error: ID is not present in the database');
                done();
              }
            };
          }).returns({ catch: catchStub });


          myFunctions.getCVEFunction(req, res);

      });
    });

  });
  });

  describe('getBulletinFunctions', () => {

    describe('without query params', () => {

      it('should return 400 bad request', (done) => {

        const req = { query: {} };
        const res = {
          status: (statusCode:any) => {
            assert.equal(statusCode, 400);
            done();
          },
          send: (result:any) => {
            assert.equal(result, 'Error: A query parameter is required.');
            done();
          }
        };

        myFunctions.getBulletinFunction(req, res);

      });
    });

    describe('getSplsCvesWithBulletinID()', () => {

      describe('with an invalid Bulletin ID', () => {

        it('should return 400 bad request', (done) => {

          const req = { query: {bulletinid: '2018'} };
          const res = {
            status: (statusCode:any) => {
              assert.equal(statusCode, 400);
              done();
            },
            send: (result:any) => {
              assert.equal(result, 'Error: Bulletin ID is malformed.');
              done();
            }
          };

          myFunctions.getBulletinFunction(req, res);

        });
      });
    });

    describe('getSplsCvesWithAndroidVersion()', () => {

      describe('with an invalid Android Version', () => {

        it('should return 400 bad request', (done) => {

          const req = { query: {androidVersion: '7.87'} };
          const res = {
            status: (statusCode:any) => {
              assert.equal(statusCode, 400);
              done();
            },
            send: (result:any) => {
              assert.equal(result, 'Error: Android Version ID is malformed');
              done();
            }
          };

          myFunctions.getBulletinFunction(req, res);

        });
      });
    });

  });

});