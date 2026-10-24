const { createClient } = require('@supabase/supabase-js');
let client;
function db(){
  if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase is not configured');
  if(!client) client=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false}});
  return client;
}
async function one(query){const {data,error}=await query.maybeSingle();if(error)throw error;return data;}
async function rows(query){const {data,error}=await query;if(error)throw error;return data||[];}
module.exports={db,one,rows};