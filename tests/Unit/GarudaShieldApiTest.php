<?php

namespace Tests\Unit;

use App\Services\GarudaShieldApi;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class GarudaShieldApiTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['services.garudashield.url' => 'http://192.168.1.103:8000/']);
    }

    public function test_summary_accepts_the_documented_api_v03_fields(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/dashboard/summary' => Http::response([
            'total_events' => 19,
            'total_alerts' => 4,
            'open_alerts' => 4,
            'failed_login_events' => 18,
            'successful_login_events' => 1,
            'critical_open_alerts' => 1,
            'high_risk_open_alerts' => 3,
            'average_open_alert_risk_score' => 56.25,
            'database' => '/data/garudashield/garudashield.db',
        ])]);

        $result = app(GarudaShieldApi::class)->summary();

        $this->assertTrue($result['ok']);
        $this->assertSame(56.25, $result['data']['average_open_alert_risk_score']);
        Http::assertSent(fn ($request) => $request->url() === 'http://192.168.1.103:8000/api/v1/dashboard/summary');
    }

    public function test_alerts_accept_the_count_and_alerts_envelope_with_evidence(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/alerts' => Http::response([
            'count' => 1,
            'alerts' => [[
                'id' => 'alert-1', 'alert_type' => 'SSH_BRUTE_FORCE', 'severity' => 'high',
                'source_ip' => '198.51.100.66', 'username' => 'analyst-test', 'failed_attempts' => 5,
                'window_minutes' => 5, 'timestamp' => '2026-10-27T06:30:51.368765+00:00',
                'status' => 'open', 'risk_score' => 70, 'description' => 'Repeated SSH login failures.',
                'evidence' => ['failed_attempts' => 5, 'threshold' => 5, 'window_minutes' => 5, 'rule' => 'SSH_BRUTE_FORCE'],
            ]],
        ])]);

        $result = app(GarudaShieldApi::class)->alerts();

        $this->assertTrue($result['ok']);
        $this->assertSame(5, $result['data']['alerts'][0]['evidence']['failed_attempts']);
    }

    public function test_alerts_schema_errors_are_not_reported_as_connection_failures(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/alerts' => Http::response(['count' => 4], 200)]);

        $result = app(GarudaShieldApi::class)->alerts();

        $this->assertFalse($result['ok']);
        $this->assertStringContainsString('struktur datanya tidak sesuai', $result['message']);
        $this->assertStringNotContainsString('terhubung', $result['message']);
    }

    public function test_events_preserve_rows_without_assuming_undocumented_fields(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/events?limit=50' => Http::response([
            'count' => 1,
            'events' => [['event_id' => 'event-1', 'custom_engine_field' => 'preserved']],
        ])]);

        $result = app(GarudaShieldApi::class)->events(50);

        $this->assertTrue($result['ok']);
        $this->assertSame('preserved', $result['rows'][0]['custom_engine_field']);
        Http::assertSent(fn ($request) => $request->url() === 'http://192.168.1.103:8000/api/v1/events?limit=50');
    }

    public function test_http_errors_are_reported_with_the_status_code(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/alerts' => Http::response(['detail' => 'unavailable'], 503)]);
        $httpError = app(GarudaShieldApi::class)->alerts();
        $this->assertFalse($httpError['ok']);
        $this->assertStringContainsString('HTTP 503', $httpError['message']);
    }

    public function test_invalid_json_is_not_reported_as_a_connection_failure(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/alerts' => Http::response('not-json', 200)]);
        $invalidJson = app(GarudaShieldApi::class)->alerts();
        $this->assertFalse($invalidJson['ok']);
        $this->assertStringContainsString('JSON yang tidak valid', $invalidJson['message']);
    }

    public function test_connection_failures_have_a_connection_specific_message(): void
    {
        Http::fake(fn () => throw new ConnectionException('connection refused'));
        $connectionError = app(GarudaShieldApi::class)->alerts();
        $this->assertFalse($connectionError['ok']);
        $this->assertStringContainsString('Tidak dapat terhubung', $connectionError['message']);
    }
}
