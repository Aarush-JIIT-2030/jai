REVOKE ALL PRIVILEGES ON TABLE public.replay_runs FROM anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.replay_runs TO authenticated;
DROP POLICY IF EXISTS "Users can delete their own replay runs" ON public.replay_runs;

REVOKE ALL PRIVILEGES ON TABLE public.flow_analysis_events FROM anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.flow_analysis_events TO authenticated;
