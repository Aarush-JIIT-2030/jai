-- Explicit service-role policy for server-side Agent 2 audit writes.
-- anon and authenticated remain denied by grants and have no policies.
CREATE POLICY "Service role can write Agent 2 audit events"
    ON public.agent2_inference_events
    FOR ALL TO service_role
    USING (true)
    WITH CHECK (true);
