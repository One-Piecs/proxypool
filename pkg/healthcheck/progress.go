package healthcheck

import (
	"sync/atomic"

	"github.com/One-Piecs/proxypool/log"
)

// progress 并发安全的进度计数器。
// 每完成 10% 输出一条日志，替代旧实现中每个节点都向 stdout 刷屏的 fmt.Printf，
// 避免并发任务下输出交错混乱。
type progress struct {
	total int64
	done  atomic.Int64
	next  atomic.Int64
}

func newProgress(total int) *progress {
	p := &progress{total: int64(total)}
	p.next.Store(10)
	return p
}

func (p *progress) inc() {
	if p.total <= 0 {
		return
	}
	done := p.done.Add(1)
	pct := done * 100 / p.total
	next := p.next.Load()
	if pct >= next && p.next.CompareAndSwap(next, next+10) {
		log.Infoln("Progress: %3d%% (%d/%d)", pct, done, p.total)
	}
}
