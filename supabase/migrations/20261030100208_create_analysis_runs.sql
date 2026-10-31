-- Baseline migration reconstructed from the live jai-hack Supabase schema.
-- This version was already applied to the production project on 2026-10-30.
CREATE TABLE public.analysis_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    dataset_name text NOT NULL,
    dataset_rows bigint NOT NULL DEFAULT 0 CHECK (dataset_rows >= 0),
    processed_rows bigint NOT NULL DEFAULT 0 CHECK (processed_rows >= 0),
    status text NOT NULL DEFAULT 'completed'
        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    model_version text,
    accuracy double precision
        CHECK (accuracy IS NULL OR (accuracy >= 0 AND accuracy <= 1)),
    macro_f1 double precision
        CHECK (macro_f1 IS NULL OR (macro_f1 >= 0 AND macro_f1 <= 1)),
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX analysis_runs_user_created_idx
    ON public.analysis_runs (user_id, created_at DESC);

ALTER TABLE public.analysis_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can create their own analysis runs"
    ON public.analysis_runs FOR INSERT TO authenticated
    WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE POLICY "Users can read their own analysis runs"
    ON public.analysis_runs FOR SELECT TO authenticated
    USING ((SELECT auth.uid()) = user_id);

CREATE POLICY "Users can update their own analysis runs"
    ON public.analysis_runs FOR UPDATE TO authenticated
    USING ((SELECT auth.uid()) = user_id)
    WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE POLICY "Users can delete their own analysis runs"
    ON public.analysis_runs FOR DELETE TO authenticated
    USING ((SELECT auth.uid()) = user_id);

GRANT ALL PRIVILEGES ON TABLE public.analysis_runs TO anon, authenticated, service_role;
