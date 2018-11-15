package ipc

import (
	"encoding/json"
	"reflect"

	log "github.com/sirupsen/logrus"
)

//Handler provides generic handling of messages
//
// Handle is called everytime a message is received
//for the registered type
type Handler interface {
	Handle(interface{}) error
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as ipc handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
type HandlerFunc func(interface{}) error

//Handle calls f(v)
func (f HandlerFunc) Handle(v interface{}) error {
	return f(v)
}

//Messenger routes messages to the proper handlers
type Messenger struct {
	registry map[string][]Handler
}

//NewMessenger creates a new Messenger
func NewMessenger() Messenger {
	return Messenger{
		registry: map[string][]Handler{},
	}
}

//Handle adds the provided handler for the given message type
func (m *Messenger) Handle(msg string, handler Handler) {
	m.registry[msg] = append(m.registry[msg], handler)
}

//HandleFunc adds a new handler for the given message type
func (m *Messenger) HandleFunc(msg string, f func(interface{}) error) {
	m.Handle(msg, HandlerFunc(f))
}

//Process received messages from the listener and routes them
//to the registered handlers. Handlers are notified sequentially based
//on the order in which they were registered
func (m Messenger) Process(msg *Message) {
	if msg == nil {
		return
	}

	handlers, ok := m.registry[msg.Type]
	if !ok || len(handlers) == 0 {
		return
	}

	var rType reflect.Type
	switch msg.Type {
	case MsgScan:
		rType = reflect.TypeOf((*Scan)(nil)).Elem()
	case MsgScanReceived:
		rType = reflect.TypeOf((*ScanReceived)(nil)).Elem()
	case MsgScanComplete:
		rType = reflect.TypeOf((*ScanComplete)(nil)).Elem()
	case MsgPluginInfo:
		rType = reflect.TypeOf((*PluginInfo)(nil)).Elem()
	default:
		log.WithFields(log.Fields{"type": msg.Type}).Warn("unknown message type")
		return
	}

	err := notify(handlers, msg, rType)
	if err != nil {
		log.WithFields(log.Fields{
			"err":  err.Error(),
			"type": msg.Type,
		}).Error("Failed to notify handlers")
		return
	}
}

func notify(handlers []Handler, msg *Message, rType reflect.Type) error {
	val := reflect.New(rType)
	err := json.Unmarshal(msg.Body, val.Interface())
	if err != nil {
		return err
	}

	i := val.Elem().Interface()

	for _, h := range handlers {
		err := h.Handle(i)
		if err != nil {
			log.WithFields(log.Fields{
				"err":  err.Error(),
				"type": msg.Type,
			}).Error("executing registered action failed")
		}
	}

	return nil
}
