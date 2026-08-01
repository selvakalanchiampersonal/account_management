/* config.js — your Supabase project connection details.
 * The anon key is meant to be public (it ships inside this file to
 * every visitor's browser) — real protection comes from Row Level
 * Security on the "vaults" table (see schema.sql), which only lets
 * a signed-in user read or write their own row.
 */
const SUPABASE_CONFIG = {
  url: 'https://ddqkezkpdngeujccyquw.supabase.co',
  anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRkcWtlemtwZG5nZXVqY2N5cXV3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU2MDAxMjgsImV4cCI6MjEwMTE3NjEyOH0.kd-2jnE7HDmIizOsSmNvxH5yVQtnTQYb6uAOo4Wttso'
};
