<?php

namespace App\Http\Controllers;

use App\Services\GarudaShieldApi;
use App\Services\TimestampPresenter;
use Illuminate\Http\Request;
use Illuminate\Http\RedirectResponse;

class DashboardController extends Controller
{
    public function __construct(private GarudaShieldApi $api, private TimestampPresenter $timestamps) {}

    public function overview()
    {
        $result = $this->api->summary();
        return view('dashboard.overview', ['page' => 'overview', 'result' => $result, 'summary' => $result['data']]);
    }

    public function events(Request $request)
    {
        $request->validate(['q' => ['nullable', 'string', 'max:120']]);
        $result = $this->api->events(50);
        $rows = $this->timestamps->newestFirst($result['rows'] ?? [], ['timestamp', 'created_at', 'event_timestamp']);
        $term = mb_strtolower((string) $request->query('q', ''));
        if ($term !== '') $rows = array_values(array_filter($rows, fn ($row) => is_array($row) && str_contains(mb_strtolower(json_encode($row) ?: ''), $term)));
        return view('dashboard.events', ['page' => 'events', 'result' => $result, 'events' => $rows, 'query' => $term]);
    }

    public function alerts(Request $request)
    {
        $request->validate(['q' => ['nullable', 'string', 'max:120']]);
        $result = $this->api->alerts();
        $rows = $this->timestamps->newestFirst($result['data']['alerts'] ?? [], ['timestamp', 'created_at', 'alert_timestamp']);
        $term = mb_strtolower((string) $request->query('q', ''));
        if ($term !== '') $rows = array_values(array_filter($rows, fn ($row) => is_array($row) && str_contains(mb_strtolower(json_encode($row) ?: ''), $term)));
        return view('dashboard.alerts', ['page' => 'alerts', 'result' => $result, 'alerts' => $rows, 'query' => $term]);
    }

    public function showAlert(string $id)
    {
        return $this->renderAlert($id);
    }

    public function analyzeAlert(string $id): RedirectResponse
    {
        $alertResult = $this->api->alerts();
        $alert = $this->findAlert($alertResult, $id);
        if (! $alertResult['ok']) {
            return redirect()->route('alerts.show', $id)->with('analysis_notice', $alertResult['message'])->with('analysis_notice_type', 'error');
        }
        if (! $alert) abort(404);

        $started = $this->api->startAlertAnalysis($id);
        if (! $started['ok']) {
            return redirect()->route('alerts.analysis', $id)->with('analysis_notice', $started['message'])->with('analysis_notice_type', 'error');
        }

        return redirect()->route('alerts.analysis', $id)->with('analysis_notice', 'Permintaan analisis dikirim. Status akan diperbarui otomatis selama proses berjalan.')->with('analysis_notice_type', 'success');
    }

    public function showAnalysis(Request $request, string $id)
    {
        $alertResult = $this->api->alerts();
        if (! $alertResult['ok']) {
            if ($request->expectsJson()) return response()->json(['ok' => false, 'message' => $alertResult['message']], 503);
            return $this->alertErrorPage($alertResult, 503);
        }
        $alert = $this->findAlert($alertResult, $id);
        if (! $alert) {
            if ($request->expectsJson()) return response()->json(['ok' => false, 'message' => 'Alert tidak ditemukan.'], 404);
            return $this->alertNotFoundPage($alertResult);
        }

        $analysisResponse = $this->api->alertAnalysis($id);
        // Some engines briefly return 404 between accepting the POST and creating its status record.
        if (! $analysisResponse['ok'] && ($analysisResponse['http_status'] ?? null) === 404) {
            $analysisResponse = ['ok' => true, 'data' => ['status' => 'pending'], 'message' => null];
        }
        $analysis = $analysisResponse['ok'] ? $this->normalizeAnalysis($analysisResponse['data']) : null;
        if ($request->expectsJson()) {
            if (! $analysisResponse['ok']) return response()->json(['ok' => false, 'message' => $analysisResponse['message']], 503);
            return response()->json(['ok' => true, ...$analysis]);
        }

        $eventResult = $this->api->events(50);
        return $this->alertDetailView($alertResult, $alert, $eventResult, $id, $analysisResponse, $analysis);
    }

    private function renderAlert(string $id)
    {
        $result = $this->api->alerts();
        if (! $result['ok']) return $this->alertErrorPage($result, 503);
        $alert = $this->findAlert($result, $id);
        if (! $alert) return $this->alertNotFoundPage($result);

        $eventResult = $this->api->events(50);
        return $this->alertDetailView($result, $alert, $eventResult, $id);
    }

    private function findAlert(array $result, string $id): ?array
    {
        if (! $result['ok']) return null;
        return collect($result['data']['alerts'])->first(fn ($row) =>
            is_array($row) && isset($row['id']) && is_string($row['id']) && hash_equals($row['id'], $id)
        );
    }

    private function alertErrorPage(array $result, int $status)
    {
        return response()->view('dashboard.alert-detail', [
            'page' => 'alerts', 'title' => 'Alert investigation', 'result' => $result,
            'alert' => null, 'events' => [], 'eventResult' => null, 'notFound' => false,
            'analysisResponse' => null, 'analysis' => null,
        ], $status);
    }

    private function alertNotFoundPage(array $result)
    {
        return response()->view('dashboard.alert-detail', [
            'page' => 'alerts', 'title' => 'Alert not found', 'result' => $result,
            'alert' => null, 'events' => [], 'eventResult' => null, 'notFound' => true,
            'analysisResponse' => null, 'analysis' => null,
        ], 404);
    }

    private function alertDetailView(array $result, array $alert, array $eventResult, string $id, ?array $analysisResponse = null, ?array $analysis = null)
    {
        return view('dashboard.alert-detail', [
            'page' => 'alerts', 'title' => 'Alert investigation', 'result' => $result,
            'alert' => $alert, 'events' => $this->matchingEvents($alert, $eventResult), 'eventResult' => $eventResult,
            'notFound' => false, 'analysisResponse' => $analysisResponse, 'analysis' => $analysis,
            'analysisPollUrl' => route('alerts.analysis', $id),
        ]);
    }

    private function matchingEvents(array $alert, array $eventResult): array
    {
        if (! $eventResult['ok']) return [];
        $ip = $this->api->value($alert, ['source_ip', 'src_ip', 'ip']);
        $username = $this->api->value($alert, ['username', 'user']);
        $alertTime = $this->timestamp($this->api->value($alert, ['timestamp', 'created_at', 'alert_timestamp']));
        $minutes = $this->api->value($alert, ['window_minutes', 'window']);
        if (! is_string($ip) || $ip === '' || ! is_string($username) || $username === '') return [];

        $orderedRows = $this->timestamps->newestFirst($eventResult['rows'] ?? [], ['timestamp', 'created_at']);
        $events = array_values(array_filter($orderedRows, function ($event) use ($ip, $username, $alertTime, $minutes) {
            if (! is_array($event)) return false;
            if ($this->api->value($event, ['source_ip', 'src_ip', 'ip']) !== $ip || $this->api->value($event, ['username', 'user']) !== $username) return false;
            $eventTime = $this->timestamp($this->api->value($event, ['timestamp', 'created_at']));
            if ($alertTime && $eventTime && is_numeric($minutes)) {
                return $eventTime->betweenIncluded($alertTime->copy()->subMinutes((int) $minutes), $alertTime->copy()->addSeconds(30));
            }
            return true;
        }));
        return array_slice($events, 0, 20);
    }

    private function normalizeAnalysis(array $payload): array
    {
        $record = is_array($payload['analysis'] ?? null) ? $payload['analysis'] : (is_array($payload['data'] ?? null) ? $payload['data'] : $payload);
        $status = strtolower((string) ($record['status'] ?? $payload['status'] ?? 'unknown'));
        if (! in_array($status, ['pending', 'running', 'completed', 'failed'], true)) $status = 'unknown';

        $analysisResult = $record['result'] ?? $record['analysis_result'] ?? $record['output'] ?? null;
        if (is_string($analysisResult)) {
            $decoded = json_decode($analysisResult, true);
            $analysisResult = is_array($decoded) ? $decoded : null;
        }
        if (! is_array($analysisResult) && array_key_exists('incident_summary', $record)) $analysisResult = $record;
        if (is_array($analysisResult['result'] ?? null)) $analysisResult = $analysisResult['result'];

        $valid = is_array($analysisResult)
            && is_string($analysisResult['incident_summary'] ?? null)
            && is_array($analysisResult['confirmed_facts'] ?? null)
            && is_array($analysisResult['hypotheses'] ?? null)
            && is_array($analysisResult['recommended_actions'] ?? null);
        return [
            'status' => $status,
            'model' => is_string($record['model'] ?? $record['model_name'] ?? $payload['model'] ?? $payload['model_name'] ?? null)
                ? ($record['model'] ?? $record['model_name'] ?? $payload['model'] ?? $payload['model_name']) : null,
            'created_at' => $record['created_at'] ?? $payload['created_at'] ?? null,
            'completed_at' => $record['completed_at'] ?? $payload['completed_at'] ?? null,
            'result' => $valid ? $analysisResult : null,
            'valid_result' => $status !== 'completed' || $valid,
        ];
    }

    private function timestamp(mixed $value): ?\Carbon\CarbonImmutable
    {
        return $this->timestamps->parse($value);
    }
}
