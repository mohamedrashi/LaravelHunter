from laravelhunter.filament.analyzer import analyze_filament_pages
from laravelhunter.models import HttpSnapshot


def snap(path: str, body: str, status: int = 200) -> HttpSnapshot:
    return HttpSnapshot(
        url=f"https://example.test{path}",
        status_code=status,
        headers={},
        cookies={},
        body_sample=body,
        elapsed_ms=10,
    )


def test_filament_inventory_extracts_components_actions_and_fields():
    body = r'''
    <html>
      <script src="/js/filament/app.js"></script>
      <div wire:name="App\Filament\Resources\UserResource\Pages\ListUsers" wire:id="abc">
        <input wire:model="tableSearch" />
        <input wire:model.live.debounce.500ms="data.email" />
        <form id="user-form" wire:submit="save">
          <input name="displayname" />
        </form>
        <button x-on:click="$wire.mountAction('create')">Create</button>
      </div>
    </html>
    '''
    pages = analyze_filament_pages([snap('/admin/users', body)])
    assert len(pages) == 1
    p = pages[0]
    assert p.path == '/admin/users'
    assert p.access_state == 'reachable'
    assert p.review_priority == 'high'
    assert any('UserResource' in x for x in p.component_names)
    assert 'create' in p.actions
    assert 'save' in p.actions
    assert 'tableSearch' in p.fields
    assert 'email' in p.fields
    assert 'displayname' in p.fields
    assert 'UserResource' in p.resource_hints


def test_review_priority_is_triage_not_based_on_http_severity():
    body = '<html><script src="/js/filament/app.js"></script><div wire:name="App\\Filament\\Pages\\ManageSynapseAdminToken"></div></html>'
    page = analyze_filament_pages([snap('/admin/manage-synapse-admin-token', body)])[0]
    assert page.review_priority == 'high'
    assert any('token' in reason for reason in page.priority_reasons)


def test_non_filament_page_is_not_added():
    pages = analyze_filament_pages([snap('/plain', '<html><input name="email"></html>')])
    assert pages == []


def test_access_state_denied():
    body = '<html><script src="/js/filament/app.js"></script></html>'
    page = analyze_filament_pages([snap('/admin/users', body, 403)])[0]
    assert page.access_state == 'denied'


def test_priority_does_not_escalate_from_shared_nested_component_or_field():
    body = r'''
    <html><script src="/js/filament/app.js"></script>
      <div wire:name="App\Filament\Pages\Dashboard"></div>
      <div wire:name="App\Filament\Livewire\UserMenu"></div>
      <input wire:model="sessionFilter" />
    </html>
    '''
    page = analyze_filament_pages([snap('/admin', body)])[0]
    assert page.review_priority == 'normal'


def test_account_list_is_normal_but_import_is_medium():
    account = analyze_filament_pages([snap('/admin/accounts', '<script src="/js/filament/app.js"></script>')])[0]
    imp = analyze_filament_pages([snap('/admin/account-imports', '<script src="/js/filament/app.js"></script>')])[0]
    assert account.review_priority == 'normal'
    assert imp.review_priority == 'medium'


def test_query_variants_merge_into_one_filament_page():
    a = snap('/admin/accounts?sort=name', '<script src="/js/filament/app.js"></script><input wire:model="tableSearch">')
    b = snap('/admin/accounts?page=2', '<script src="/js/filament/app.js"></script><button wire:click="sortTable(\'name\')"></button><button x-on:click="$wire.mountTableAction(\'edit\', 1)"></button>')
    pages = analyze_filament_pages([a, b])
    assert len(pages) == 1
    assert pages[0].path == '/admin/accounts'
    assert 'edit' in pages[0].actions
    assert 'sortTable' not in pages[0].actions


def test_internal_livewire_plumbing_is_not_counted_as_application_action_or_field():
    body = r'''
    <html><script src="/js/filament/app.js"></script>
      <button wire:click="$refresh"></button>
      <button wire:click="sortTable('name')"></button>
      <button wire:click="$wire.mountAction('create')"></button>
      <input wire:model="mountedActions.0.data.name" />
      <input wire:model="data.email" />
    </html>
    '''
    page = analyze_filament_pages([snap('/admin/accounts', body)])[0]
    assert 'create' in page.actions
    assert '$refresh' not in page.actions
    assert 'sortTable' not in page.actions
    assert 'email' in page.fields
    assert all(not f.startswith('mountedActions.') for f in page.fields)


def test_v07_correlates_resource_page_type_and_action_contexts():
    body = r'''
    <html><script src="/js/filament/app.js"></script>
      <div wire:name="App\Filament\Resources\UserResource\Pages\ListUsers"></div>
      <button x-on:click="$wire.mountAction('create')">Create</button>
      <button x-on:click="$wire.mountTableAction('edit', 12)">Edit</button>
      <button x-on:click="$wire.mountTableBulkAction('delete')">Delete selected</button>
      <form wire:submit="save"><input wire:model="data.email"></form>
      <input wire:model="tableSearch">
    </html>
    '''
    page = analyze_filament_pages([snap('/admin/users', body)])[0]
    assert page.resource_classes == ['UserResource']
    assert page.page_classes == ['ListUsers']
    assert page.page_types == ['list']
    assert 'create' in page.page_actions
    assert 'edit' in page.table_actions
    assert 'delete' in page.bulk_actions
    assert 'save' in page.submit_actions
    assert 'email' in page.form_fields
    assert 'tableSearch' in page.table_state_fields
    assert 'table-record-action:edit' in page.authorization_surfaces
    assert 'bulk-action:delete' in page.authorization_surfaces


def test_v07_record_identifier_is_review_surface_not_finding():
    body = r'''<html><script src="/js/filament/app.js"></script>
    <div wire:name="App\Filament\Resources\GroupResource\Pages\ViewGroup"></div></html>'''
    page = analyze_filament_pages([snap('/admin/groups/6', body)])[0]
    assert 'record-identifier:path' in page.authorization_surfaces
    assert 'resource-page:view' in page.authorization_surfaces
    assert page.page_types == ['view']


def test_v07_direct_submit_is_not_misclassified_as_table_action():
    body = r'''<html><script src="/js/filament/app.js"></script>
    <form wire:submit="authenticate"><input name="email"></form></html>'''
    page = analyze_filament_pages([snap('/admin/login', body)])[0]
    assert page.submit_actions == ['authenticate']
    assert page.table_actions == []
    assert page.bulk_actions == []


def test_v071_ui_state_methods_do_not_inflate_application_actions():
    body = r'''
    <html><script src="/js/filament/app.js"></script>
      <div wire:name="App\Filament\Pages\ListAccounts"></div>
      <button wire:click="applyTableFilters"></button>
      <button wire:click="resetTableColumnManager"></button>
      <button wire:click="setAccountChipFilter('active')"></button>
      <button x-on:click="$wire.mountAction('syncFromSynapse')"></button>
    </html>
    '''
    page = analyze_filament_pages([snap('/admin/accounts', body)])[0]
    assert 'syncFromSynapse' in page.page_actions
    assert 'applyTableFilters' not in page.actions
    assert 'resetTableColumnManager' not in page.actions
    assert 'setAccountChipFilter' not in page.actions
    assert 'applyTableFilters' in page.ui_state_actions
    assert 'resetTableColumnManager' in page.ui_state_actions
    assert 'setAccountChipFilter' in page.ui_state_actions


def test_v071_selection_helpers_are_ui_state_not_authz_actions():
    body = r'''
    <html><script src="/js/filament/app.js"></script>
      <div wire:name="App\Filament\Pages\CreateGroup"></div>
      <button wire:click="selectAllMatchingCreateGroupAccounts"></button>
      <button wire:click="selectVisibleCreateGroupAccounts"></button>
      <button wire:click="clearCreateGroupAccounts"></button>
      <form wire:submit="create"><input name="name"></form>
    </html>
    '''
    page = analyze_filament_pages([snap('/admin/groups/create', body)])[0]
    assert page.submit_actions == ['create']
    assert page.page_actions == []
    assert len(page.ui_state_actions) == 3
    assert all(not x.startswith('page-action:') for x in page.authorization_surfaces)
    assert 'resource-page:create' in page.authorization_surfaces
