import {OIDC} from '../../../src/lib/OIDC';

const oidc = new OIDC();

describe('OIDC class', () => {

  it('routes() should return an object', () => {
    expect(oidc.routes()).toBeInstanceOf(Object);
  });
  
});