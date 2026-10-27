package gateway

import (
	"context"
	"testing"
)

// Заглушка Approver для тестов шлюза и MCP-прокси: возвращает заданный итог
// и вызывает wait заданное число раз.
func stubApprover(res ApprovalResult, ticks int, got *[]ApprovalRequest) Approver {
	return ApproverFunc(func(_ context.Context, req ApprovalRequest, wait func()) ApprovalResult {
		if got != nil {
			*got = append(*got, req)
		}
		for range ticks {
			if wait != nil {
				wait()
			}
		}
		return res
	})
}

func TestNoApproverDenies(t *testing.T) {
	r := NoApprover.Await(context.Background(), ApprovalRequest{Tool: "x"}, nil)
	if r.Approved() || r.State != ApprovalUnavailable {
		t.Fatalf("без сервера вызов не подтверждается: %+v", r)
	}
}

func TestApprovalAgentMessage(t *testing.T) {
	cases := []struct {
		state ApprovalState
		rule  string
		want  string
	}{
		{ApprovalDenied, "", approvalDeniedMessage},
		{ApprovalDenied, "Нужен дежурный", "Нужен дежурный"},
		{ApprovalCancelled, "", approvalDeniedMessage},
		{ApprovalTimeout, "Нужен дежурный", approvalTimeoutMessage},
		{ApprovalInterrupted, "", approvalTimeoutMessage},
		{ApprovalQueueFull, "Нужен дежурный", approvalFailedMessage},
		{ApprovalUnavailable, "", approvalFailedMessage},
	}
	for _, c := range cases {
		r := ApprovalResult{State: c.state, Comment: "секретный комментарий дежурного"}
		if got := r.AgentMessage(c.rule); got != c.want {
			t.Errorf("%s: %q, ожидалось %q", c.state, got, c.want)
		}
	}
}

func TestStubApproverTicks(t *testing.T) {
	var reqs []ApprovalRequest
	n := 0
	a := stubApprover(ApprovalResult{ID: "id", State: ApprovalApproved}, 3, &reqs)
	r := a.Await(context.Background(), ApprovalRequest{Tool: "files/delete"}, func() { n++ })
	if !r.Approved() || n != 3 || len(reqs) != 1 || reqs[0].Tool != "files/delete" {
		t.Fatalf("заглушка: %+v, тиков %d, запросов %d", r, n, len(reqs))
	}
}
