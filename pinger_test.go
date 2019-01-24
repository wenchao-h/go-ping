package ping

import (
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnicast(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	pinger, err := New("0.0.0.0", "::")
	require.NoError(err)
	require.NotNil(pinger)
	defer pinger.Close()

	for _, target := range []string{"127.0.0.1", "::1"} {
		rtt, err := pinger.PingAttempts(&net.IPAddr{IP: net.ParseIP(target)}, time.Second, 2)
		assert.NoError(err, target)
		assert.NotZero(rtt, target)
	}

	_, err = pinger.PingAttempts(&net.IPAddr{IP: net.ParseIP("192.0.2.0")}, 0, 1)
	require.EqualError(err, "i/o timeout")

	tErr := err.(*timeoutError)
	assert.True(tErr.Timeout())
	assert.True(tErr.Temporary())
}

func TestMulticast(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	pinger, err := New("", "::")
	require.NoError(err)
	require.NotNil(pinger)
	defer pinger.Close()

	replyChan, err := pinger.PingMulticast(&net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: "eth0"}, time.Second)
	assert.NoError(err)
	assert.NotNil(replyChan)

	var replies []Reply
	for reply := range replyChan {
		replies = append(replies, reply)
	}

	assert.NotZero(len(replies))
}

func TestDestinationUnreachable(t *testing.T) {
	assert := assert.New(t)

	for _, test := range []struct {
		protocol int
		id       uint16
		sequence uint16
		fixture  string
	}{
		{
			protocol: ProtocolICMP,
			id:       11351,
			sequence: 1,
			fixture:  "fixtures/destination-unreachable-v4",
		},
		{
			protocol: ProtocolICMPv6,
			id:       2620,
			sequence: 4,
			fixture:  "fixtures/destination-unreachable-v6",
		},
	} {

		pinger := Pinger{
			id:       test.id,
			requests: make(map[uint16]request),
		}

		req := simpleRequest{}
		pinger.requests[test.sequence] = &req

		pinger.receiveFixture(test.protocol, test.fixture, net.IP{31, 209, 95, 154}, time.Time{})
		rtt, err := req.roundTripTime()
		assert.EqualError(err, "destination unreachable")
		assert.Equal(time.Duration(0), rtt)
	}

}

func (pinger *Pinger) receiveFixture(proto int, path string, addr net.IP, t time.Time) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	pinger.receive(proto, data, addr, t)
}
