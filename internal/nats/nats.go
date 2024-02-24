package nats

import (
	"fmt"
	"time"

	// "github.com/nats-io/nats.go"

	natsserver "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
)

type Client struct {
	nats.JetStreamContext
}

const (
	streamName     = "EVENTS"
	streamSubjects = "EVENTS.*"
)

var consumer, publisher *Client

func StartServer() (*natsserver.Server, error) {
	ns, err := natsserver.NewServer(
		&natsserver.Options{
			JetStream: true,
		})
	if err != nil {
		return nil, err
	}
	go ns.Start()

	if !ns.ReadyForConnections(3 * time.Second) {
		return nil, fmt.Errorf("connection timeout")
	}

	consumer = new(Client)
	publisher = new(Client)

	if err := consumer.SetJetStreamContext(nats.DefaultURL); err != nil {
		return nil, err
	}
	if err := publisher.SetJetStreamContext(nats.DefaultURL); err != nil {
		return nil, err
	}

	if err := consumer.createStream(); err != nil {
		return nil, err
	}

	return ns, nil
}

func (client *Client) SetJetStreamContext(addr string) error {
	nc, err := nats.Connect(addr)
	if err != nil {
		return err
	}

	jsc, err := nc.JetStream(nats.PublishAsyncMaxPending(256))
	if err != nil {
		return err
	}

	client.JetStreamContext = jsc
	return nil
}

func GetConsumer() *Client {
	return consumer
}

func GetPublisher() *Client {
	return publisher
}

func (client *Client) ConsumeMsg() (chan string, error) {
	c := make(chan string, 20)
	_, err := client.JetStreamContext.Subscribe(streamSubjects, func(m *nats.Msg) {
		if err := m.Ack(); err != nil {
			return
		}
		c <- string(m.Data)
	},
		nats.DeliverNew())

	if err != nil {
		return nil, err
	}

	return c, nil
}

func (client *Client) PublishMsg(id, msg string) error {
	if _, err := client.JetStreamContext.Publish(streamName+"."+id, []byte(msg), nats.MsgId(id)); err != nil {
		return err
	}
	return nil
}

func (client *Client) createStream() error {
	stream, err := client.JetStreamContext.StreamInfo(streamName)
	if err != nil {
		if err != nats.ErrStreamNotFound {
			return err
		}
	}
	if stream == nil {
		_, err = client.JetStreamContext.AddStream(&nats.StreamConfig{
			Name:                 streamName,
			Subjects:             []string{streamSubjects},
			Duplicates:           5 * time.Second,
			MaxAge:               5 * time.Second,
			MaxMsgsPerSubject:    1,
			DiscardNewPerSubject: true,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
