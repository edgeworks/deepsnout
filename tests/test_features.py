import pytest
from deepsnout.features import Diversity,service_group,psl_available


@pytest.mark.parametrize('size',[0,1,10,100,1000,10000])
def test_fixed_diversity(size):
    sketch=Diversity()
    for i in range(size): sketch.add(str(i)); sketch.add(str(i))
    assert len(sketch.encode())==344
    assert abs(sketch.estimate()-size)<=max(1,size*.2)
    assert Diversity(sketch.encode()).estimate()==sketch.estimate()


def test_psl_private_and_fallback(monkeypatch):
    if psl_available():
        assert service_group('api.example.co.uk')=='example.co.uk'
        assert service_group('a.tenant.github.io')=='tenant.github.io'
    monkeypatch.setattr('deepsnout.features._PSL',None)
    assert service_group('a.tenant.github.io')=='a.tenant.github.io'
