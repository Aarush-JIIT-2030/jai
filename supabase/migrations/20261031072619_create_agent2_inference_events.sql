-- Server-only Agent 2 audit events. Raw network-flow records are never stored.
CREATE TABLE public.agent2_inference_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    source text NOT NULL CHECK (source IN ('agent2_independent', 'pipeline_analysis')),
    model_version text NOT NULL DEFAULT 'agent2-isolation-forest',
    anomaly_score double precision NOT NULL
        CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
    is_anomaly boolean NOT NULL,
    feature_count integer NOT NULL DEFAULT 0 CHECK (feature_count >= 0),
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    request_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX agent2_inference_events_created_at_idx
    ON public.agent2_inference_events (created_at DESC);

ALTER TABLE public.agent2_inference_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON TABLE public.agent2_inference_events FROM anon, authenticated;
GRANT INSERT, SELECT ON TABLE public.agent2_inference_events TO service_role;
