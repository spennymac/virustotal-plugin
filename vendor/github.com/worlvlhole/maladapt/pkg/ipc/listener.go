package ipc

import (
	"errors"
	"runtime"

	log "github.com/sirupsen/logrus"
)

var (
	// ErrConsumerClosed will be returned if the provided consumer
	// is closed
	ErrConsumerClosed = errors.New("consumer closed unexpectedly")
)

//Processor passes received messages on to be consumed
type Processor interface {
	Process(*Message)
}

//Listener allows multiple parties to listen to a
//single consumer
type Listener struct {
	consumer  Consumer
	processor Processor
}

//Listen begins consuming messages from the given consumer and
//providing any received messages to the processor
func Listen(consumer Consumer, processor Processor) error {
	listener := &Listener{consumer: consumer, processor: processor}
	return listener.Listen()
}

//Listen consumes and decomposes messages. Any successfully decomposed
//messages are given to the processor for consumption
func (l *Listener) Listen() error {
	c := make(chan int, runtime.GOMAXPROCS(0))
	for d := range l.consumer.Consume() {
		c <- 1
		go func(d Decomposer) {
			defer func() {
				<-c
			}()
			msg, err := d.Decompose()
			if err != nil {
				log.WithFields(log.Fields{
					"err": err.Error(),
				}).Error("Failed to decompose message")
				return
			}

			log.WithField("type", msg.Type).Info("message received")
			l.processor.Process(msg)
		}(d)
	}

	return ErrConsumerClosed
}
