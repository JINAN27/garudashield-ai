<?php

namespace Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class AlertInvestigationTest extends TestCase
{
    private const ALERT_ID = '9c61c742-3d9c-47f8-a28d-79c36b1c0e21';

    protected function setUp(): void
    {
        parent::setUp();
        config(['services.garudashield.url' => 'http://192.168.1.103:8000']);
        $this->withSession(['dashboard_authenticated' => true]);
    }

    private function alert(array $overrides = []): array
    {
        return array_replace([
            'id' => self::ALERT_ID, 'alert_type' => 'SSH_BRUTE_FORCE', 'severity' => 'high',
            'risk_score' => 70, 'source_ip' => '198.51.100.66', 'username' => 'analyst-test',
            'failed_attempts' => 5, 'window_minutes' => 5,
            'timestamp' => '2026-10-27T06:30:51+00:00', 'status' => 'open',
            'evidence' => ['failed_attempts' => 5, 'rule' => 'SSH_BRUTE_FORCE'],
        ], $overrides);
    }

    private function fakeAlerts(array $alerts): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/alerts' => Http::response(['count' => count($alerts), 'alerts' => $alerts])]);
    }

    public function test_detail_shows_the_exact_alert_and_only_contextually_matching_event_candidates(): void
    {
        $this->fakeAlerts([$this->alert()]);
        Http::fake(['192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['events' => [
            ['id' => 'ev-match', 'event_type' => 'SSH_LOGIN_FAILED', 'source_ip' => '198.51.100.66', 'username' => 'analyst-test', 'timestamp' => '2026-10-27T06:29:00+00:00'],
            ['id' => 'ev-wrong-user', 'event_type' => 'SSH_LOGIN_FAILED', 'source_ip' => '198.51.100.66', 'username' => 'someone-else', 'timestamp' => '2026-10-27T06:29:00+00:00'],
            ['id' => 'ev-outside-window', 'event_type' => 'SSH_LOGIN_FAILED', 'source_ip' => '198.51.100.66', 'username' => 'analyst-test', 'timestamp' => '2026-10-27T06:10:00+00:00'],
        ]])]);

        $this->get(route('alerts.show', self::ALERT_ID))->assertOk()
            ->assertSee(self::ALERT_ID)->assertSee('Alert overview')->assertSee('Detection evidence')
            ->assertSee('ev-match')->assertDontSee('ev-wrong-user')->assertDontSee('ev-outside-window')
            ->assertSee('contextual correlation only');
    }

    public function test_alert_list_links_to_details_using_the_alert_id(): void
    {
        $this->fakeAlerts([$this->alert()]);
        $this->get(route('alerts'))->assertOk()->assertSee(route('alerts.show', self::ALERT_ID), false);
    }

    public function test_alert_and_event_lists_order_explicit_instants_newest_first(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [
                $this->alert(['id' => 'older-alert', 'timestamp' => '2026-11-12T01:00:00Z']),
                $this->alert(['id' => 'newer-alert', 'timestamp' => '2026-11-12T09:00:00+07:00']),
            ]]),
            '192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['events' => [
                ['id' => 'older-event', 'timestamp' => '2026-11-12T01:00:00Z', 'event_type' => 'SSH_LOGIN_FAILED'],
                ['id' => 'newer-event', 'timestamp' => '2026-11-12T09:00:00+07:00', 'event_type' => 'SSH_LOGIN_FAILED'],
            ]]),
        ]);

        $this->get(route('alerts'))->assertOk()->assertSeeInOrder(['newer-alert', 'older-alert'])
            ->assertSeeInOrder(['12 Nov 2026, 09:00:00 WIB', '12 Nov 2026, 08:00:00 WIB']);
        $this->get(route('events'))->assertOk()->assertSeeInOrder(['newer-event', 'older-event'])
            ->assertSeeInOrder(['12 Nov 2026, 09:00:00 WIB', '12 Nov 2026, 08:00:00 WIB']);
    }

    public function test_unknown_alert_id_returns_a_styled_404(): void
    {
        $this->fakeAlerts([$this->alert()]);
        $this->get(route('alerts.show', 'missing-id'))->assertNotFound()->assertSee('Alert not found')->assertDontSee('Stack trace');
    }

    public function test_alert_api_timeout_returns_a_safe_service_unavailable_page(): void
    {
        Http::fake(fn () => throw new ConnectionException('private internal exception detail'));
        $this->get(route('alerts.show', self::ALERT_ID))->assertStatus(503)
            ->assertSee('Alert details could not be loaded')->assertDontSee('private internal exception detail');
    }

    public function test_optional_fields_and_missing_events_are_handled_without_exposing_markup(): void
    {
        $this->fakeAlerts([$this->alert(['evidence' => ['note' => '<script>alert(1)</script>'], 'description' => null, 'risk_score' => null])]);
        Http::fake(['192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['events' => []])]);

        $this->get(route('alerts.show', self::ALERT_ID))->assertOk()
            ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', false)
            ->assertDontSee('<script>alert(1)</script>', false)->assertSee('No matching event candidates');
    }

    public function test_event_api_failure_does_not_hide_the_alert(): void
    {
        $this->fakeAlerts([$this->alert(['evidence' => null])]);
        Http::fake(['192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['detail' => 'down'], 503)]);

        $this->get(route('alerts.show', self::ALERT_ID))->assertOk()
            ->assertSee(self::ALERT_ID)->assertSee('Events could not be loaded')->assertSee('No structured evidence supplied');
    }

    public function test_existing_dashboard_overview_still_renders(): void
    {
        Http::fake(['192.168.1.103:8000/api/v1/dashboard/summary' => Http::response([
            'total_events' => 19, 'total_alerts' => 4, 'open_alerts' => 4, 'failed_login_events' => 18,
            'successful_login_events' => 1, 'critical_open_alerts' => 1, 'high_risk_open_alerts' => 3,
            'average_open_alert_risk_score' => 56.25,
        ])]);

        $this->get(route('dashboard'))->assertOk()->assertSee('Threat overview')->assertSee('19');
    }

    public function test_analyze_action_posts_to_fastapi_then_redirects_to_status_page(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analyze' => Http::response(['status' => 'pending'], 202),
        ]);

        $this->post(route('alerts.analyze', self::ALERT_ID))->assertRedirect(route('alerts.analysis', self::ALERT_ID));

        Http::assertSent(fn ($request) => $request->method() === 'POST'
            && $request->url() === 'http://192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analyze');
    }

    public function test_analyze_api_failure_returns_a_safe_dashboard_message(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analyze' => Http::response(['detail' => 'internal stack'], 503),
        ]);

        $this->post(route('alerts.analyze', self::ALERT_ID))
            ->assertRedirect(route('alerts.analysis', self::ALERT_ID))
            ->assertSessionHas('analysis_notice', 'API detection engine mengembalikan HTTP 503.');
    }

    public function test_analysis_status_endpoint_returns_safe_json_for_polling(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analysis' => Http::response(['status' => 'running', 'model' => 'garudashield-soc-v2']),
        ]);

        $this->getJson(route('alerts.analysis', self::ALERT_ID))->assertOk()
            ->assertJsonPath('status', 'running')->assertJsonPath('model', 'garudashield-soc-v2');
    }

    public function test_completed_ai_result_is_rendered_as_separate_structured_sections(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analysis' => Http::response([
                'status' => 'completed', 'model' => 'garudashield-soc-v2',
                'created_at' => '2026-11-12T01:30:15Z', 'completed_at' => '2026-11-12T08:30:15+07:00',
                'result' => [
                    'incident_summary' => 'Repeated SSH login failures were detected.',
                    'confirmed_facts' => ['Five failed attempts were recorded.'],
                    'hypotheses' => ['The source may be an unauthorized client.'],
                    'recommended_actions' => ['Verify the source IP with the system owner.'],
                ],
            ]),
            '192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['events' => []]),
        ]);

        $this->get(route('alerts.analysis', self::ALERT_ID))->assertOk()
            ->assertSee('Incident Summary')->assertSee('Repeated SSH login failures were detected.')
            ->assertSee('Facts stated by analysis')->assertSee('Hypotheses')->assertSee('Recommended Actions')
            ->assertSee('garudashield-soc-v2')->assertSee('not confirmed incidents')
            ->assertSee('12 Nov 2026, 08:30:15 WIB');
    }

    public function test_pending_and_failed_analysis_states_are_presented_without_engine_error_details(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analysis' => Http::response(['status' => 'failed', 'error' => 'private stack trace']),
            '192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['events' => []]),
        ]);

        $this->get(route('alerts.analysis', self::ALERT_ID))->assertOk()
            ->assertSee('Analysis failed')->assertSee('Analyze with AI')->assertDontSee('private stack trace');
    }

    public function test_completed_analysis_with_invalid_result_shows_safe_schema_warning(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analysis' => Http::response(['status' => 'completed', 'result' => ['incident_summary' => 'partial']]),
            '192.168.1.103:8000/api/v1/events?limit=50' => Http::response(['events' => []]),
        ]);

        $this->get(route('alerts.analysis', self::ALERT_ID))->assertOk()
            ->assertSee('Analysis response was incomplete')->assertSee('Analyze with AI');
    }

    public function test_status_api_failure_is_reported_without_stack_trace(): void
    {
        Http::fake([
            '192.168.1.103:8000/api/v1/alerts' => Http::response(['alerts' => [$this->alert()]]),
            '192.168.1.103:8000/api/v1/alerts/'.self::ALERT_ID.'/analysis' => Http::response(['detail' => 'sensitive server detail'], 503),
        ]);

        $this->getJson(route('alerts.analysis', self::ALERT_ID))->assertStatus(503)
            ->assertJsonPath('ok', false)->assertDontSee('sensitive server detail');
    }
}
