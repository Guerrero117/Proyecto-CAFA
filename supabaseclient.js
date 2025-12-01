import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm";

export const supabase = createClient(
    postgresql://postgres:[YOUR_PASSWORD]@db.rhscaieuhyzlsgnwvxll.supabase.co:5432/postgres
    db.rhscaieuhyzlsgnwvxll.supabase.co
);
