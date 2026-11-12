@extends('dashboard.layout', ['title' => $title])
@section('content')
<div class="page-heading"><div><div class="eyebrow">SECURITY OPERATIONS CENTER <span> / </span> INVESTIGATIONS</div><h1>{{ $notFound ? 'Alert not found' : ($alert ? 'Alert investigation' : 'Investigation unavailable') }}</h1><p>{{ $notFound ? 'This alert ID is not present in the detection engine response.' : 'Review the detection evidence and available surrounding context.' }}</p></div><a class="button subtle" href="{{ route('alerts') }}">← Back to alerts</a></div>
@if($notFound)
<section class="panel investigation-card"><h2>Alert unavailable</h2><p>No alert with this ID was returned by the detection engine. The alert list may have changed since it was opened.</p><a class="button subtle" href="{{ route('alerts') }}">Return to alert queue</a></section>
@elseif(!$alert)
<div class="notice error"><span class="notice-icon">!</span><div><b>Alert details could not be loaded</b><p>{{ $result['message'] ?? 'The detection engine is unavailable.' }}</p><small>Try again after the detection engine is reachable.</small></div></div>
@else
@php($api=app(\App\Services\GarudaShieldApi::class))
@php($type=strtoupper((string)$api->value($alert,['alert_type','rule','type'])))
@php($severity=$api->value($alert,['severity']))
@php($score=$api->value($alert,['risk_score','score']))
@php($evidence=$alert['evidence'] ?? null)
<section class="investigation-grid">
<article class="panel investigation-card"><div class="panel-heading"><div><h2>Alert overview</h2><p>Detection record returned by the engine</p></div><span class="severity {{ in_array(strtolower((string)$severity),['critical','high','medium','low']) ? strtolower((string)$severity) : 'unknown' }}"><i></i>{{ $severity ?? 'Unknown severity' }}</span></div>
<dl class="detail-fields">
<div><dt>Alert ID</dt><dd class="mono">{{ $alert['id'] ?? '—' }}</dd></div><div><dt>Alert type</dt><dd>{{ $api->humanType($type ?: 'unknown') }}</dd></div>
<div><dt>Risk score</dt><dd>{{ is_numeric($score) ? number_format((float)$score, 0) : '—' }}</dd></div><div><dt>Status</dt><dd>{{ $api->value($alert,['status','state']) ?? '—' }}</dd></div>
<div><dt>Source IP</dt><dd class="mono">{{ $api->value($alert,['source_ip','src_ip','ip']) ?? '—' }}</dd></div><div><dt>Username</dt><dd>{{ $api->value($alert,['username','user']) ?? '—' }}</dd></div>
<div><dt>Failed attempts</dt><dd>{{ $api->value($alert,['failed_attempts','attempts']) ?? '—' }}</dd></div><div><dt>Detection window</dt><dd>{{ ($window=$api->value($alert,['window_minutes','window'])) !== null ? $window.' minutes' : '—' }}</dd></div>
<div class="wide"><dt>Timestamp</dt><dd>{{ app(\App\Services\TimestampPresenter::class)->format($api->value($alert,['timestamp','created_at','alert_timestamp'])) }}</dd></div>
@if($api->value($alert,['description']))<div class="wide"><dt>Description</dt><dd>{{ $api->value($alert,['description']) }}</dd></div>@endif
</dl></article>
<article class="panel investigation-card"><div class="panel-heading"><div><h2>Analyst guidance</h2><p>Suggested review steps for this signal</p></div></div>
@if($type === 'SSH_BRUTE_FORCE')<p>Repeated failed SSH logins matched the configured source and account threshold. This signal alone does not establish that an account was accessed.</p><ol class="guidance-list"><li>Verify whether the source IP belongs to an expected administrator, VPN, or monitoring service.</li><li>Review failed authentication times and attempt volume against the configured threshold.</li><li>Check the account owner and recent access activity; follow your incident response process if the activity is unexpected.</li></ol>
@elseif($type === 'SSH_SUCCESS_AFTER_FAILURES')<p>A successful SSH login followed repeated failures within the configured detection window. Confirm the context before deciding whether access was unauthorized.</p><ol class="guidance-list"><li>Verify the source IP, account owner, and whether the successful login was expected.</li><li>Review the preceding failed attempts and the successful login time together.</li><li>If unexpected, follow your incident response process to contain access and preserve relevant records.</li></ol>
@else<p>This alert type does not have a specific investigation guide in the dashboard.</p><ol class="guidance-list"><li>Review the evidence and validate the source and affected account.</li><li>Compare with expected activity and consult the detection rule owner if needed.</li><li>Follow your incident response process if the activity is unexpected.</li></ol>@endif</article>
<article class="panel investigation-card evidence-card"><div class="panel-heading"><div><h2>Detection evidence</h2><p>Evidence values are escaped API text; source timestamps remain unmodified here.</p></div></div>
@if(is_array($evidence) && count($evidence))<dl class="evidence-fields">@foreach($evidence as $key=>$value)<div><dt>{{ is_string($key) ? str_replace('_',' ',$key) : 'Evidence' }}</dt><dd>@if(is_scalar($value) || $value === null){{ $value ?? '—' }}@else{{ json_encode($value, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE) }}@endif</dd></div>@endforeach</dl>
@elseif(is_string($evidence) && $evidence !== '')<pre class="evidence-raw">{{ $evidence }}</pre>
@else<div class="empty-state compact"><b>No structured evidence supplied</b><p>The engine did not include an evidence object for this alert.</p></div>@endif
<details class="raw-record"><summary>View raw alert record (API timestamp formats are preserved)</summary><pre>{{ json_encode($alert, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE) }}</pre></details></article>
<article class="panel investigation-card evidence-card"><div class="panel-heading"><div><h2>Matching event candidates</h2><p>At most 20 events from the latest 50 records.</p></div></div>
<p class="investigation-note">These candidates match the alert's source IP and username, and when timestamps and a detection window are available, fall within that window. This is contextual correlation only; it does not prove that an event caused the alert.</p>
@if(empty($eventResult['ok']))<div class="notice error"><div><b>Events could not be loaded</b><p>{{ $eventResult['message'] ?? 'Event API unavailable.' }}</p></div></div>
@elseif(count($events))<div class="table-wrap"><table><thead><tr><th>EVENT TYPE</th><th>SOURCE IP</th><th>USERNAME</th><th>TIMESTAMP</th><th>EVENT ID</th></tr></thead><tbody>@foreach($events as $event)<tr><td>{{ $api->value($event,['event_type','type']) ?? '—' }}</td><td class="mono">{{ $api->value($event,['source_ip','src_ip','ip']) ?? '—' }}</td><td>{{ $api->value($event,['username','user']) ?? '—' }}</td><td class="muted-cell">{{ app(\App\Services\TimestampPresenter::class)->format($api->value($event,['timestamp','created_at'])) }}</td><td class="mono">{{ $api->value($event,['id','event_id']) ?? '—' }}</td></tr>@endforeach</tbody></table></div>
@else<div class="empty-state compact"><b>No matching event candidates</b><p>Available event records did not match both the alert's source IP and username. This does not rule out related activity outside the latest 50 records.</p></div>@endif
</article></section>
<article class="panel ai-analysis-panel" id="ai-analysis-panel" data-analysis-state="{{ $analysis['status'] ?? '' }}" data-analysis-poll-url="{{ $analysisPollUrl ?? '' }}">
<div class="panel-heading"><div><div class="eyebrow">AI ASSISTED TRIAGE</div><h2>Analysis with AI</h2><p>FastAPI routes analysis to the configured local model; Laravel does not contact Ollama directly.</p></div>@if($analysis)<span class="analysis-status {{ $analysis['status'] }}">{{ ucfirst($analysis['status']) }}</span>@endif</div>
<p class="ai-disclaimer">AI output is decision support. Validate statements against source records; an alert or AI hypothesis alone does not confirm a compromise.</p>
@if(session('analysis_notice'))<div class="notice {{ session('analysis_notice_type') === 'error' ? 'error' : '' }}"><div><b>{{ session('analysis_notice_type') === 'error' ? 'Analysis request issue' : 'Analysis request' }}</b><p>{{ session('analysis_notice') }}</p></div></div>@endif
@if($analysisResponse && empty($analysisResponse['ok']))<div class="notice error"><span class="notice-icon">!</span><div><b>Analysis status could not be retrieved</b><p>{{ $analysisResponse['message'] }}</p></div></div>@endif
@if($analysis)
    @if($analysis['created_at'] || $analysis['completed_at'])<div class="analysis-time-meta">@if($analysis['created_at'])<span>Created</span><b>{{ app(\App\Services\TimestampPresenter::class)->format($analysis['created_at']) }}</b>@endif @if($analysis['completed_at'])<span>Completed</span><b>{{ app(\App\Services\TimestampPresenter::class)->format($analysis['completed_at']) }}</b>@endif</div>@endif
    @if(in_array($analysis['status'], ['pending','running'], true))
        <div class="analysis-progress"><span class="analysis-spinner" aria-hidden="true"></span><div><b>Analysis {{ $analysis['status'] === 'pending' ? 'queued' : 'in progress' }}</b><p id="analysis-refresh-message">This may take about 40–70 seconds. Status checks run every 8 seconds for up to 96 seconds.</p></div></div>
    @elseif($analysis['status'] === 'failed')
        <div class="notice error"><span class="notice-icon">!</span><div><b>Analysis failed</b><p>The analysis engine could not complete this request. You may retry it.</p></div></div>
    @elseif($analysis['status'] === 'completed' && empty($analysis['valid_result']))
        <div class="notice error"><span class="notice-icon">!</span><div><b>Analysis response was incomplete</b><p>The engine reported completion but did not return all expected result fields.</p></div></div>
    @elseif($analysis['status'] === 'completed' && is_array($analysis['result']))
        <div class="analysis-meta"><span>Model</span><b>{{ $analysis['model'] ?: 'Not provided by engine' }}</b><span>Status</span><b>Completed</b></div>
        <section class="ai-result"><h3>Incident Summary</h3><p>{{ $analysis['result']['incident_summary'] }}</p></section>
        <div class="ai-result-grid">
            <section class="ai-result"><h3>Facts stated by analysis</h3><p class="ai-result-note">Validate independently against source records.</p>@if(count($analysis['result']['confirmed_facts']))<ul>@foreach($analysis['result']['confirmed_facts'] as $fact)<li>{{ is_scalar($fact) ? $fact : json_encode($fact, JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE) }}</li>@endforeach</ul>@else<p class="muted-cell">No facts returned.</p>@endif</section>
            <section class="ai-result hypotheses"><h3>Hypotheses</h3><p class="ai-result-note">Possibilities for investigation; not confirmed incidents.</p>@if(count($analysis['result']['hypotheses']))<ul>@foreach($analysis['result']['hypotheses'] as $hypothesis)<li>{{ is_scalar($hypothesis) ? $hypothesis : json_encode($hypothesis, JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE) }}</li>@endforeach</ul>@else<p class="muted-cell">No hypotheses returned.</p>@endif</section>
        </div>
        <section class="ai-result actions"><h3>Recommended Actions</h3>@if(count($analysis['result']['recommended_actions']))<ol>@foreach($analysis['result']['recommended_actions'] as $action)<li>{{ is_scalar($action) ? $action : json_encode($action, JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE) }}</li>@endforeach</ol>@else<p class="muted-cell">No recommended actions returned.</p>@endif</section>
    @endif
@endif
<div class="analysis-controls">
    @if(!$analysis || in_array($analysis['status'], ['failed','unknown'], true) || ($analysis['status'] === 'completed' && empty($analysis['valid_result'])))
        <form method="post" action="{{ route('alerts.analyze', $alert['id']) }}" class="analyze-form">@csrf<button class="button analyze-button" type="submit">Analyze with AI</button></form>
    @endif
    <a class="button subtle" href="{{ route('alerts.analysis', $alert['id']) }}">Refresh analysis status</a>
</div>
</article>
@endif
@endsection
@push('scripts')
@if($alert && isset($analysis) && in_array($analysis['status'] ?? '', ['pending','running'], true))
<script>
(() => {
    const panel = document.getElementById('ai-analysis-panel');
    const message = document.getElementById('analysis-refresh-message');
    const endpoint = panel?.dataset.analysisPollUrl;
    if (!endpoint) return;
    let checks = 0;
    const timer = window.setInterval(async () => {
        checks += 1;
        try {
            const response = await fetch(endpoint, {headers: {'Accept': 'application/json'}, credentials: 'same-origin'});
            if (!response.ok) throw new Error('Status request failed');
            const data = await response.json();
            if (data.status === 'completed' || data.status === 'failed') {
                window.clearInterval(timer);
                window.location.reload();
                return;
            }
            if (data.status === 'pending' || data.status === 'running') {
                const label = data.status === 'pending' ? 'queued' : 'in progress';
                message.textContent = `Analysis ${label}. Status checked ${checks} time(s).`;
            }
        } catch (_) {
            message.textContent = 'Could not refresh status just now; polling will retry.';
        }
        if (checks >= 12) {
            window.clearInterval(timer);
            message.textContent = 'Automatic checks stopped after 96 seconds. Use “Refresh analysis status” to check again.';
        }
    }, 8000);
})();
document.querySelectorAll('.analyze-form').forEach(form => form.addEventListener('submit', () => {
    const button = form.querySelector('button[type="submit"]');
    if (button) { button.disabled = true; button.textContent = 'Submitting…'; }
}));
</script>
@else
<script>document.querySelectorAll('.analyze-form').forEach(form => form.addEventListener('submit', () => { const button=form.querySelector('button[type="submit"]'); if(button){button.disabled=true;button.textContent='Submitting…';} }));</script>
@endif
@endpush
