package notify

import (
	"strings"
	"testing"
	"time"
)

// Allow clicked again and again on a notification that keeps coming back, each click within notifyMature of the last
// time it came back: the first click came too soon after it appeared, and is asked again in place, saying so. The
// clicks after that count from when the notification first appeared, so the user isn't caught in a loop of early
// clicks on a notification that reappears under the pointer
func TestNotificationEarlyClicksAgain(t *testing.T) {
	notifyMature = 300 * time.Millisecond
	t.Cleanup(func() { notifyMature = time.Second })
	addr, f := testBus(t)
	id, answer := ask(t, addr, f)
	f.click(t, id, "Allow")
	for range 10 {
		select {
		case again := <-f.posted:
			f.mu.Lock()
			body := f.bodies[again]
			f.mu.Unlock()
			if again != id || !strings.Contains(body, "too soon") {
				t.Fatalf("Asked again as %d (first %d), body %q", again, id, body)
			}
		case a := <-answer:
			if a != "allow" {
				t.Errorf("Allow answered %q", a)
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("Neither asked again nor answered")
		}
		time.Sleep(notifyMature / 3)
		f.click(t, id, "Allow")
	}
	t.Fatal("Every click came too soon after the notification came back")
}

// A server that closes a notification on any action (no resident hint): an early click is asked again in a new
// notification, whose clicks count from its own appearance
func TestNotificationEarlyClosed(t *testing.T) {
	notifyMature = 300 * time.Millisecond
	t.Cleanup(func() { notifyMature = time.Second })
	addr, f := testBus(t)
	f.mu.Lock()
	f.closes = true
	f.mu.Unlock()
	id, answer := ask(t, addr, f)
	f.click(t, id, "Allow")
	var again uint32
	select {
	case again = <-f.posted:
	case a := <-answer:
		t.Fatalf("An early click answered %q", a)
	case <-time.After(5 * time.Second):
		t.Fatal("Not asked again")
	}
	if again == id {
		t.Fatalf("Asked again in the closed notification %d", id)
	}
	f.click(t, again, "Allow")
	select {
	case <-f.posted:
	case a := <-answer:
		t.Fatalf("A click at once on the new notification answered %q", a)
	case <-time.After(5 * time.Second):
		t.Fatal("Not asked again")
	}
}
