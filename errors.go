package skbtrace

import "fmt"

// Represents skbtrace instance which originated error
// Useful for tracking chain of errors
type ErrorLevel string

// Helper for prettier unwrapping errors
type Error interface {
	Level() ErrorLevel
	Ident() string

	NextError() error

	Message() string
}

const (
	ErrMsgNotFound     = "not found"
	ErrMsgParseError   = "parse error"
	ErrMsgNotSpecified = "instance name is not specified"
)

const (
	ErrLevelProbe     ErrorLevel = "probe"
	ErrLevelRow       ErrorLevel = "row"
	ErrLevelObject    ErrorLevel = "object"
	ErrLevelFilter    ErrorLevel = "filter"
	ErrLevelField     ErrorLevel = "field"
	ErrLevelStructDef ErrorLevel = "structdef"
)

type errorImpl struct {
	level ErrorLevel
	ident string
	err   error
	msg   string
}

func newErrorf(
	level ErrorLevel, ident string, err error,
	fmtstr string, args ...interface{},
) *errorImpl {
	return &errorImpl{
		level: level,
		ident: ident,
		err:   err,
		msg:   fmt.Sprintf(fmtstr, args...),
	}
}

func newCommonError(level ErrorLevel, ident string, msg string) *errorImpl {
	return newErrorf(level, ident, nil, msg)
}

func (ewm *errorImpl) Level() ErrorLevel {
	return ewm.level
}

func (ewm *errorImpl) Ident() string {
	return ewm.ident
}

func (ewm *errorImpl) NextError() error {
	return ewm.err
}

func (ewm *errorImpl) Message() string {
	return ewm.msg
}

func (ewm *errorImpl) Error() string {
	msg := fmt.Sprintf("error in %s '%s'", ewm.level, ewm.ident)
	if ewm.msg != "" {
		msg = fmt.Sprintf("%s: %s", msg, ewm.msg)
	}
	if ewm.err != nil {
		msg = fmt.Sprintf("%s: %v", msg, ewm.err)
	}
	return msg
}
