-- The analysis history is private to signed-in users.
-- RLS remains the row-level authorization boundary; SQL grants are least-privilege.
REVOKE ALL PRIVILEGES ON TABLE public.analysis_runs FROM anon;
REVOKE ALL PRIVILEGES ON TABLE public.analysis_runs FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.analysis_runs TO authenticated;
